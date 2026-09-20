package server

import (
	"context"
	"crypto/sha1"
	"errors"
	"log/slog"
	"net"

	"github.com/jake-scott/kcmex/internal/kcmproto"
	"github.com/jake-scott/kcmex/internal/krb5c"
)

// Server answers the KCM protocol for a single fixed cache backed by an
// internal/krb5c.Client.
type Server struct {
	krb       *krb5c.Client
	cacheName string
	cacheUUID kcmproto.UUID
	uid       uint32
	log       *slog.Logger
}

// New builds a Server. cacheName is the KCM cache name kcmex advertises
// for GET_DEFAULT_CACHE / GEN_NEW (conventionally the daemon's own
// uid, matching MIT's "KCM:%{uid}" convention); ownerUID is the uid
// every connecting peer must match (kcmex is single-user only).
func New(krb *krb5c.Client, cacheName string, ownerUID uint32, log *slog.Logger) *Server {
	if log == nil {
		log = slog.Default()
	}
	return &Server{
		krb:       krb,
		cacheName: cacheName,
		cacheUUID: uuidOfString(cacheName),
		uid:       ownerUID,
		log:       log,
	}
}

func uuidOfString(s string) kcmproto.UUID {
	sum := sha1.Sum([]byte("kcmex-cache:" + s))
	var u kcmproto.UUID
	copy(u[:], sum[:16])
	return u
}

// Serve accepts connections on l until it returns an error (typically
// because l was closed).
func (s *Server) Serve(l *net.UnixListener) error {
	for {
		conn, err := l.AcceptUnix()
		if err != nil {
			return err
		}
		go s.handleConn(conn)
	}
}

func (s *Server) handleConn(conn *net.UnixConn) {
	defer conn.Close()
	s.log.Debug("connection accepted")

	uid, err := peerUID(conn)
	if err != nil {
		s.log.Warn("could not verify peer credentials; closing connection", "error", err)
		return
	}
	if uid != s.uid {
		s.log.Warn("rejecting connection from unexpected uid", "peer_uid", uid, "expected_uid", s.uid)
		return
	}
	s.log.Debug("peer credentials verified", "uid", uid)

	for {
		body, err := kcmproto.ReadMessage(conn)
		if err != nil {
			s.log.Debug("connection closed / read error", "error", err)
			return // client disconnected, or a framing error - either way, done
		}
		code, payload := s.dispatch(body)
		if err := kcmproto.WriteReply(conn, code, payload); err != nil {
			s.log.Debug("write error", "error", err)
			return
		}
	}
}

func errorCode(err error) int32 {
	var kerr *krb5c.Error
	if errors.As(err, &kerr) {
		return kerr.Code
	}
	return krb5c.CCNoSupp
}

// dispatch decodes one request body and returns the reply code and
// payload to send back (see kcmproto.WriteReply for how those two are
// framed on the wire).
func (s *Server) dispatch(body []byte) (int32, []byte) {
	op, rest, err := kcmproto.ParseRequestHeader(body)
	if err != nil {
		s.log.Warn("malformed request", "request_len", len(body), "error", err)
		return krb5c.CCNoSupp, nil
	}
	log := s.log.With("op", op.String())

	var cname string
	if kcmproto.HasLeadingName(op) {
		// kcmex has exactly one cache, so the requested name is accepted
		// without validation - the socket's peer-uid check is the real
		// access boundary here, not the cache name string.
		cname, rest, err = kcmproto.SplitCName(rest)
		if err != nil {
			log.Warn("malformed request: missing cache name")
			return krb5c.CCNoSupp, nil
		}
		log = log.With("cache", cname)
	}

	if log.Enabled(context.Background(), slog.LevelDebug) {
		log.Debug("request", s.requestAttrs(op, rest)...)
	}

	if !kcmproto.Supported(op) {
		log.Debug("unsupported opcode", "opcode_num", uint16(op))
		return krb5c.CCNoSupp, nil
	}

	code, payload := s.handle(log, op, rest)
	log.Debug("reply", "code", code, "status", s.krb.ErrorMessage(code), "payload_len", len(payload))
	return code, payload
}

// requestAttrs decodes the opcode-specific part of a request purely for
// debug logging, returning slog key/value pairs describing what the
// client asked for. rest is the body with the header and any leading
// cache name already stripped. Decoding failures are reported as an
// attribute rather than an error: the handler proper will reject the
// request and log a warning itself.
func (s *Server) requestAttrs(op kcmproto.Opcode, rest []byte) []any {
	attrs := []any{"body_len", len(rest)}

	switch op {
	case kcmproto.OpGetCacheByUUID, kcmproto.OpGetCredByUUID:
		uuids, err := kcmproto.ReadUUIDList(rest)
		if err != nil {
			return append(attrs, "decode_error", err)
		}
		strs := make([]string, len(uuids))
		for i, u := range uuids {
			strs[i] = u.String()
		}
		return append(attrs, "uuids", strs)

	case kcmproto.OpRetrieve, kcmproto.OpRemoveCred:
		flags, mcWire, err := kcmproto.ReadUint32(rest)
		if err != nil {
			return append(attrs, "decode_error", err)
		}
		attrs = append(attrs, "flags", kcmproto.MatchFlagsString(flags))
		mc, err := kcmproto.UnmarshalMatchCredential(mcWire)
		if err != nil {
			return append(attrs, "decode_error", err)
		}
		return append(attrs, "match", mc.String())

	case kcmproto.OpStore:
		summary, err := s.krb.SummarizeCredential(rest)
		if err != nil {
			return append(attrs, "decode_error", err)
		}
		return append(attrs, "cred", summary.String())

	case kcmproto.OpInitialize:
		p, _, err := kcmproto.UnmarshalPrincipal(rest)
		if err != nil {
			return append(attrs, "decode_error", err)
		}
		return append(attrs, "principal", p.UnparseName(), "name_type", p.Type)

	case kcmproto.OpSetKDCOffset:
		offset, _, err := kcmproto.ReadUint32(rest)
		if err != nil {
			return append(attrs, "decode_error", err)
		}
		return append(attrs, "offset", int32(offset))
	}
	return attrs
}

// handle performs a supported operation. rest is the request body with
// the header and any leading cache name already stripped.
func (s *Server) handle(log *slog.Logger, op kcmproto.Opcode, rest []byte) (int32, []byte) {
	switch op {
	case kcmproto.OpNoop:
		return 0, nil

	case kcmproto.OpGenNew, kcmproto.OpGetDefaultCache:
		return 0, kcmproto.PutCName(s.cacheName)

	case kcmproto.OpSetDefaultCache:
		return 0, nil

	case kcmproto.OpGetCacheUUIDList:
		return 0, kcmproto.PutUUIDList([]kcmproto.UUID{s.cacheUUID})

	case kcmproto.OpGetCacheByUUID:
		uuids, err := kcmproto.ReadUUIDList(rest)
		if err != nil || len(uuids) != 1 || uuids[0] != s.cacheUUID {
			return krb5c.CCNotFound, nil
		}
		return 0, kcmproto.PutCName(s.cacheName)

	case kcmproto.OpGetPrincipal:
		p, err := s.krb.DefaultPrincipal()
		if err != nil {
			log.Warn("operation failed", "error", err)
			return errorCode(err), nil
		}
		return 0, kcmproto.MarshalPrincipal(p)

	case kcmproto.OpGetCredUUIDList:
		entries, err := s.krb.ListEntries()
		if err != nil {
			log.Warn("operation failed", "error", err)
			return errorCode(err), nil
		}
		uuids := make([]kcmproto.UUID, len(entries))
		for i, e := range entries {
			uuids[i] = e.UUID
		}
		return 0, kcmproto.PutUUIDList(uuids)

	case kcmproto.OpGetCredByUUID:
		uuids, err := kcmproto.ReadUUIDList(rest)
		if err != nil || len(uuids) != 1 {
			return krb5c.CCNotFound, nil
		}
		e, ok, err := s.krb.EntryByUUID(uuids[0])
		if err != nil {
			log.Warn("operation failed", "error", err)
			return errorCode(err), nil
		}
		if !ok {
			return krb5c.CCNotFound, nil
		}
		return 0, e.Wire

	case kcmproto.OpGetCredList:
		entries, err := s.krb.ListEntries()
		if err != nil {
			log.Warn("operation failed", "error", err)
			return errorCode(err), nil
		}
		payload := kcmproto.PutUint32(uint32(len(entries)))
		for _, e := range entries {
			payload = append(payload, kcmproto.PutUint32(uint32(len(e.Wire)))...)
			payload = append(payload, e.Wire...)
		}
		return 0, payload

	case kcmproto.OpRemoveCred:
		if len(rest) < 4 {
			return krb5c.CCNoSupp, nil
		}
		// The leading 4 bytes are match flags (see RemoveMatching's doc for
		// why they're not translated/honored yet); the rest is a
		// match-credential in the sparse Heimdal format k5_marshal_mcred
		// produces - distinct from the full-credential format used
		// everywhere else on the wire.
		mc, err := kcmproto.UnmarshalMatchCredential(rest[4:])
		if err != nil {
			log.Warn("malformed match-credential", "error", err)
			return krb5c.CCNoSupp, nil
		}
		if err := s.krb.RemoveMatching(mc); err != nil {
			log.Warn("operation failed", "error", err)
			return errorCode(err), nil
		}
		return 0, nil

	case kcmproto.OpRetrieve:
		if len(rest) < 4 {
			return krb5c.CCNoSupp, nil
		}
		// The leading 4 bytes are the KCM_TC_*/KCM_GC_CACHED flags word.
		// It is intentionally never inspected: kcmex always allows a real
		// TGS-REQ on a cache miss, regardless of whether the client set
		// KCM_GC_CACHED ("cache only, don't ask the KDC"). The rest is a
		// match-credential in the sparse Heimdal format k5_marshal_mcred
		// produces, not the full-credential format krb5_unmarshal_credentials
		// expects.
		mc, err := kcmproto.UnmarshalMatchCredential(rest[4:])
		if err != nil {
			log.Warn("malformed match-credential", "error", err)
			return krb5c.CCNoSupp, nil
		}
		wire, err := s.krb.Retrieve(mc)
		if err != nil {
			// Not-found is routine (the client probes for ccache config
			// entries this way); anything else is worth surfacing.
			if errorCode(err) == krb5c.CCNotFound {
				log.Debug("no matching credential", "error", err)
			} else {
				log.Info("could not obtain a ticket", "error", err)
			}
			return errorCode(err), nil
		}
		return 0, wire

	case kcmproto.OpStore:
		if err := s.krb.Store(rest); err != nil {
			log.Warn("operation failed", "error", err)
			return errorCode(err), nil
		}
		return 0, nil

	case kcmproto.OpInitialize:
		p, _, err := kcmproto.UnmarshalPrincipal(rest)
		if err != nil {
			return krb5c.CCNoSupp, nil
		}
		if err := s.krb.Initialize(p); err != nil {
			log.Warn("operation failed", "error", err)
			return errorCode(err), nil
		}
		return 0, nil

	case kcmproto.OpDestroy:
		if p, err := s.krb.DefaultPrincipal(); err == nil {
			_ = s.krb.Initialize(p) // clears entries, keeps the same identity
		}
		return 0, nil

	case kcmproto.OpGetKDCOffset:
		return 0, kcmproto.PutUint32(0)

	case kcmproto.OpSetKDCOffset:
		return 0, nil

	default:
		return krb5c.CCNoSupp, nil
	}
}
