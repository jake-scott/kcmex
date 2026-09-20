package kcmproto

import (
	"encoding/hex"
	"fmt"
	"strings"
	"time"
)

// opcodeNames maps each Opcode to its kcm.h enumerator name minus the
// KCM_OP_ prefix, for human-readable logging.
var opcodeNames = map[Opcode]string{
	OpNoop:             "NOOP",
	OpGetName:          "GET_NAME",
	OpResolve:          "RESOLVE",
	OpGenNew:           "GEN_NEW",
	OpInitialize:       "INITIALIZE",
	OpDestroy:          "DESTROY",
	OpStore:            "STORE",
	OpRetrieve:         "RETRIEVE",
	OpGetPrincipal:     "GET_PRINCIPAL",
	OpGetCredUUIDList:  "GET_CRED_UUID_LIST",
	OpGetCredByUUID:    "GET_CRED_BY_UUID",
	OpRemoveCred:       "REMOVE_CRED",
	OpSetFlags:         "SET_FLAGS",
	OpChown:            "CHOWN",
	OpChmod:            "CHMOD",
	OpGetInitialTicket: "GET_INITIAL_TICKET",
	OpGetTicket:        "GET_TICKET",
	OpMoveCache:        "MOVE_CACHE",
	OpGetCacheUUIDList: "GET_CACHE_UUID_LIST",
	OpGetCacheByUUID:   "GET_CACHE_BY_UUID",
	OpGetDefaultCache:  "GET_DEFAULT_CACHE",
	OpSetDefaultCache:  "SET_DEFAULT_CACHE",
	OpGetKDCOffset:     "GET_KDC_OFFSET",
	OpSetKDCOffset:     "SET_KDC_OFFSET",
	OpAddNTLMCred:      "ADD_NTLM_CRED",
	OpHaveNTLMCred:     "HAVE_NTLM_CRED",
	OpDelNTLMCred:      "DEL_NTLM_CRED",
	OpDoNTLMAuth:       "DO_NTLM_AUTH",
	OpGetNTLMUserList:  "GET_NTLM_USER_LIST",
	OpGetCredList:      "GET_CRED_LIST",
	OpReplace:          "REPLACE",
}

// String returns the opcode's kcm.h name (e.g. "GET_PRINCIPAL"), or
// "OPCODE(n)" for a value kcm.h does not define.
func (op Opcode) String() string {
	if name, ok := opcodeNames[op]; ok {
		return name
	}
	return fmt.Sprintf("OPCODE(%d)", uint16(op))
}

// matchFlagNames lists the RETRIEVE/REMOVE_CRED flag bits with their
// kcm.h names, highest bit first so the rendered order is stable.
var matchFlagNames = []struct {
	bit  uint32
	name string
}{
	{FlagTCDontMatchRealm, "TC_DONT_MATCH_REALM"},
	{FlagTCMatchKeytype, "TC_MATCH_KEYTYPE"},
	{FlagTCMatchSrvNameonly, "TC_MATCH_SRV_NAMEONLY"},
	{FlagTCMatchFlagsExact, "TC_MATCH_FLAGS_EXACT"},
	{FlagTCMatchFlags, "TC_MATCH_FLAGS"},
	{FlagTCMatchTimesExact, "TC_MATCH_TIMES_EXACT"},
	{FlagTCMatchTimes, "TC_MATCH_TIMES"},
	{FlagTCMatchAuthdata, "TC_MATCH_AUTHDATA"},
	{FlagTCMatch2ndTkt, "TC_MATCH_2ND_TKT"},
	{FlagTCMatchIsSkey, "TC_MATCH_IS_SKEY"},
	{FlagGCCached, "GC_CACHED"},
}

// MatchFlagsString renders a RETRIEVE/REMOVE_CRED flags word as a
// '|'-separated list of kcm.h flag names, with any bits kcm.h does not
// define shown in hex. A zero word renders as "0".
func MatchFlagsString(flags uint32) string {
	if flags == 0 {
		return "0"
	}
	var parts []string
	for _, f := range matchFlagNames {
		if flags&f.bit != 0 {
			parts = append(parts, f.name)
			flags &^= f.bit
		}
	}
	if flags != 0 {
		parts = append(parts, fmt.Sprintf("0x%08x", flags))
	}
	return strings.Join(parts, "|")
}

// String renders u as 32 lowercase hex digits.
func (u UUID) String() string {
	return hex.EncodeToString(u[:])
}

// String is UnparseName, so a Principal prints in its conventional
// text form wherever it is formatted with %v or logged.
func (p Principal) String() string {
	return p.UnparseName()
}

// FormatTimestamp renders a Kerberos timestamp (seconds since the Unix
// epoch, transported as a 32-bit value that MIT treats as unsigned) as
// RFC 3339 UTC, or "0" when unset.
func FormatTimestamp(ts int32) string {
	if ts == 0 {
		return "0"
	}
	return time.Unix(int64(uint32(ts)), 0).UTC().Format(time.RFC3339)
}

// String summarises which fields the match-credential carries, in a
// single "key=value ..." line suitable for a log record. Only the
// fields present on the wire are shown, and secret material (session
// key contents) and ticket bytes are reported by length alone.
func (mc MatchCredential) String() string {
	var b strings.Builder
	if mc.HasClient {
		fmt.Fprintf(&b, "client=%s ", mc.Client.UnparseName())
	}
	if mc.HasServer {
		fmt.Fprintf(&b, "server=%s ", mc.Server.UnparseName())
	}
	if mc.HasSessionKey {
		fmt.Fprintf(&b, "enctype=%d key_len=%d ", mc.KeyType, len(mc.KeyData))
	}
	if mc.AuthTime != 0 {
		fmt.Fprintf(&b, "authtime=%s ", FormatTimestamp(mc.AuthTime))
	}
	if mc.StartTime != 0 {
		fmt.Fprintf(&b, "starttime=%s ", FormatTimestamp(mc.StartTime))
	}
	if mc.EndTime != 0 {
		fmt.Fprintf(&b, "endtime=%s ", FormatTimestamp(mc.EndTime))
	}
	if mc.RenewTill != 0 {
		fmt.Fprintf(&b, "renew_till=%s ", FormatTimestamp(mc.RenewTill))
	}
	if mc.IsSKey {
		b.WriteString("is_skey=true ")
	}
	if mc.TicketFlags != 0 {
		fmt.Fprintf(&b, "ticket_flags=0x%08x ", mc.TicketFlags)
	}
	if mc.HasTicket {
		fmt.Fprintf(&b, "ticket_len=%d ", len(mc.Ticket))
	}
	if mc.HasSecondTicket {
		fmt.Fprintf(&b, "second_ticket_len=%d ", len(mc.SecondTicket))
	}
	if b.Len() == 0 {
		return "(empty)"
	}
	return strings.TrimSuffix(b.String(), " ")
}
