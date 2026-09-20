package kcmproto

import "fmt"

// Principal is a plain-data Kerberos principal name: a name type, a
// realm, and its slash-separated components (e.g. "HTTP", "host.example.com"
// for HTTP/host.example.com@REALM).
type Principal struct {
	Type       int32
	Realm      string
	Components []string
}

// MarshalPrincipal encodes p in the structural layout MIT's v4 FILE
// ccache format uses for a principal: name-type, component count, the
// realm (length-prefixed), then each component (length-prefixed).
//
// MIT krb5 does not export a public function for marshalling a bare
// principal (only whole credentials, via krb5_marshal_credentials), so
// this one small, non-cryptographic structural encoding is hand-written
// here; it mirrors the same documented byte layout MIT's own FILE ccache
// code and krb5_marshal_credentials use for the principal fields inside
// a credential record.
func MarshalPrincipal(p Principal) []byte {
	out := PutUint32(uint32(p.Type))
	out = append(out, PutUint32(uint32(len(p.Components)))...)
	out = append(out, PutUint32(uint32(len(p.Realm)))...)
	out = append(out, p.Realm...)
	for _, c := range p.Components {
		out = append(out, PutUint32(uint32(len(c)))...)
		out = append(out, c...)
	}
	return out
}

// UnmarshalPrincipal decodes a principal encoded by MarshalPrincipal
// (or by the MIT client, which uses the identical layout) and returns
// the number of bytes consumed from body.
func UnmarshalPrincipal(body []byte) (p Principal, n int, err error) {
	nameType, rest, err := ReadUint32(body)
	if err != nil {
		return Principal{}, 0, fmt.Errorf("principal name-type: %w", err)
	}
	numComponents, rest, err := ReadUint32(rest)
	if err != nil {
		return Principal{}, 0, fmt.Errorf("principal component count: %w", err)
	}
	realmLen, rest, err := ReadUint32(rest)
	if err != nil {
		return Principal{}, 0, fmt.Errorf("principal realm length: %w", err)
	}
	if uint32(len(rest)) < realmLen {
		return Principal{}, 0, ErrTruncated
	}
	realm := string(rest[:realmLen])
	rest = rest[realmLen:]

	comps := make([]string, 0, numComponents)
	for i := uint32(0); i < numComponents; i++ {
		var clen uint32
		clen, rest, err = ReadUint32(rest)
		if err != nil {
			return Principal{}, 0, fmt.Errorf("principal component %d length: %w", i, err)
		}
		if uint32(len(rest)) < clen {
			return Principal{}, 0, ErrTruncated
		}
		comps = append(comps, string(rest[:clen]))
		rest = rest[clen:]
	}

	consumed := len(body) - len(rest)
	return Principal{Type: int32(nameType), Realm: realm, Components: comps}, consumed, nil
}

// UnparseName renders p in the conventional "component/component@REALM"
// text form, escaping any literal '\\', '/', '@' and whitespace-control
// characters in each component per MIT krb5's principal quoting rules,
// so the result can be safely fed to krb5_parse_name.
func (p Principal) UnparseName() string {
	out := ""
	for i, c := range p.Components {
		if i > 0 {
			out += "/"
		}
		out += escapeComponent(c)
	}
	if p.Realm != "" {
		out += "@" + escapeComponent(p.Realm)
	}
	return out
}

func escapeComponent(s string) string {
	out := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		switch c := s[i]; c {
		case '\\', '/', '@':
			out = append(out, '\\', c)
		case '\t':
			out = append(out, '\\', 't')
		case '\n':
			out = append(out, '\\', 'n')
		case '\b':
			out = append(out, '\\', 'b')
		case 0:
			out = append(out, '\\', '0')
		default:
			out = append(out, c)
		}
	}
	return string(out)
}
