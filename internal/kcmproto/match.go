package kcmproto

import "fmt"

// Match-credential header bits, from k5_marshal_mcred's mcred_header() in
// MIT's src/lib/krb5/ccache/ccmarshal.c. KCM_OP_RETRIEVE and
// KCM_OP_REMOVE_CRED send a match-credential in this format - NOT the
// same format krb5_marshal_credentials/krb5_unmarshal_credentials use
// for whole credentials (that one has no header and always includes
// both principals). Feeding a match-credential to
// krb5_unmarshal_credentials fails with "bad format": this is a
// separate, sparser structural encoding that only MIT's own (private,
// unexported) k5_marshal_mcred produces, so kcmex must decode it by
// hand - a small, purely structural piece of code with no
// cryptographic content, mirroring what MIT's own marshal function
// does field-for-field.
const (
	scClientPrincipal uint32 = 0x0001
	scServerPrincipal uint32 = 0x0002
	scSessionKey      uint32 = 0x0004
	scTicket          uint32 = 0x0008
	scSecondTicket    uint32 = 0x0010
	scAuthdata        uint32 = 0x0020
	scAddresses       uint32 = 0x0040
)

// MatchCredential is a decoded KCM_OP_RETRIEVE / KCM_OP_REMOVE_CRED
// match-credential: a sparse template of which fields to match against
// (only the fields whose Has* flag is set were present on the wire).
type MatchCredential struct {
	HasClient bool
	Client    Principal
	HasServer bool
	Server    Principal

	HasSessionKey bool
	KeyType       int32
	KeyData       []byte

	AuthTime, StartTime, EndTime, RenewTill int32
	IsSKey                                  bool
	TicketFlags                             uint32

	HasTicket       bool
	Ticket          []byte
	HasSecondTicket bool
	SecondTicket    []byte
	// Addresses and authdata are parsed (to keep the cursor correctly
	// positioned) but not retained: kcmex does not support matching or
	// forwarding these fields. See package docs.
}

func readUint16(body []byte) (v uint16, rest []byte, err error) {
	if len(body) < 2 {
		return 0, nil, ErrTruncated
	}
	return uint16(body[0])<<8 | uint16(body[1]), body[2:], nil
}

// UnmarshalMatchCredential decodes a KCM_OP_RETRIEVE / KCM_OP_REMOVE_CRED
// match-credential per MIT's k5_marshal_mcred layout: a header bitmask,
// then each optional field the header indicates is present, in a fixed
// order, then the always-present timestamps/is_skey/ticket_flags, then
// any remaining optional fields.
func UnmarshalMatchCredential(body []byte) (MatchCredential, error) {
	var mc MatchCredential

	header, rest, err := ReadUint32(body)
	if err != nil {
		return mc, fmt.Errorf("match-credential header: %w", err)
	}

	if header&scClientPrincipal != 0 {
		p, n, err := UnmarshalPrincipal(rest)
		if err != nil {
			return mc, fmt.Errorf("match-credential client principal: %w", err)
		}
		mc.HasClient = true
		mc.Client = p
		rest = rest[n:]
	}
	if header&scServerPrincipal != 0 {
		p, n, err := UnmarshalPrincipal(rest)
		if err != nil {
			return mc, fmt.Errorf("match-credential server principal: %w", err)
		}
		mc.HasServer = true
		mc.Server = p
		rest = rest[n:]
	}
	if header&scSessionKey != 0 {
		enctype, r, err := readUint16(rest)
		if err != nil {
			return mc, fmt.Errorf("match-credential key enctype: %w", err)
		}
		rest = r
		keylen, r, err := ReadUint32(rest)
		if err != nil {
			return mc, fmt.Errorf("match-credential key length: %w", err)
		}
		if uint32(len(r)) < keylen {
			return mc, ErrTruncated
		}
		mc.HasSessionKey = true
		mc.KeyType = int32(enctype)
		mc.KeyData = append([]byte(nil), r[:keylen]...)
		rest = r[keylen:]
	}

	var authtime, starttime, endtime, renewTill uint32
	for _, dst := range []*uint32{&authtime, &starttime, &endtime, &renewTill} {
		v, r, err := ReadUint32(rest)
		if err != nil {
			return mc, fmt.Errorf("match-credential times: %w", err)
		}
		*dst = v
		rest = r
	}
	mc.AuthTime, mc.StartTime, mc.EndTime, mc.RenewTill =
		int32(authtime), int32(starttime), int32(endtime), int32(renewTill)

	if len(rest) < 1 {
		return mc, ErrTruncated
	}
	mc.IsSKey = rest[0] != 0
	rest = rest[1:]

	flags, rest, err := ReadUint32(rest)
	if err != nil {
		return mc, fmt.Errorf("match-credential ticket flags: %w", err)
	}
	mc.TicketFlags = flags

	if header&scAddresses != 0 {
		rest, err = skipAddressOrAuthdataList(rest)
		if err != nil {
			return mc, fmt.Errorf("match-credential addresses: %w", err)
		}
	}
	if header&scAuthdata != 0 {
		rest, err = skipAddressOrAuthdataList(rest)
		if err != nil {
			return mc, fmt.Errorf("match-credential authdata: %w", err)
		}
	}
	if header&scTicket != 0 {
		n, r, err := ReadUint32(rest)
		if err != nil {
			return mc, fmt.Errorf("match-credential ticket length: %w", err)
		}
		if uint32(len(r)) < n {
			return mc, ErrTruncated
		}
		mc.HasTicket = true
		mc.Ticket = append([]byte(nil), r[:n]...)
		rest = r[n:]
	}
	if header&scSecondTicket != 0 {
		n, r, err := ReadUint32(rest)
		if err != nil {
			return mc, fmt.Errorf("match-credential second ticket length: %w", err)
		}
		if uint32(len(r)) < n {
			return mc, ErrTruncated
		}
		mc.HasSecondTicket = true
		mc.SecondTicket = append([]byte(nil), r[:n]...)
		rest = r[n:]
	}

	return mc, nil
}

// skipAddressOrAuthdataList consumes a count-prefixed list of
// (type uint16, length-prefixed data) entries - the shared layout
// marshal_addrs and marshal_authdata both use - and returns what
// follows it.
func skipAddressOrAuthdataList(body []byte) ([]byte, error) {
	count, rest, err := ReadUint32(body)
	if err != nil {
		return nil, err
	}
	for i := uint32(0); i < count; i++ {
		_, r, err := readUint16(rest) // type
		if err != nil {
			return nil, err
		}
		n, r2, err := ReadUint32(r)
		if err != nil {
			return nil, err
		}
		if uint32(len(r2)) < n {
			return nil, ErrTruncated
		}
		rest = r2[n:]
	}
	return rest, nil
}
