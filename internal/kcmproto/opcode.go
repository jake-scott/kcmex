// Package kcmproto implements the wire-level KCM (Kerberos Credential
// Manager) protocol spoken by the MIT krb5 client's "KCM:" credential
// cache type. It only deals with the outer envelope: opcode framing,
// flag words, UUID lists, and the small structural encodings (like a
// bare principal) that MIT does not expose a public marshalling
// function for. Actual credential bytes are produced/consumed by
// internal/krb5c via the real libkrb5 krb5_marshal_credentials /
// krb5_unmarshal_credentials calls; this package never touches
// Kerberos crypto or ticket contents.
//
// Reference: src/include/kcm.h and src/lib/krb5/ccache/cc_kcm.c in
// https://github.com/krb5/krb5 (MIT krb5).
package kcmproto

// Opcode identifies a KCM operation. Values match the kcm_opcode enum
// in MIT's src/include/kcm.h exactly (implicit sequential values from
// KCM_OP_NOOP, plus the MIT extensions starting at 13000).
type Opcode uint16

const (
	OpNoop             Opcode = 0
	OpGetName          Opcode = 1
	OpResolve          Opcode = 2
	OpGenNew           Opcode = 3
	OpInitialize       Opcode = 4
	OpDestroy          Opcode = 5
	OpStore            Opcode = 6
	OpRetrieve         Opcode = 7
	OpGetPrincipal     Opcode = 8
	OpGetCredUUIDList  Opcode = 9
	OpGetCredByUUID    Opcode = 10
	OpRemoveCred       Opcode = 11
	OpSetFlags         Opcode = 12
	OpChown            Opcode = 13
	OpChmod            Opcode = 14
	OpGetInitialTicket Opcode = 15
	OpGetTicket        Opcode = 16
	OpMoveCache        Opcode = 17
	OpGetCacheUUIDList Opcode = 18
	OpGetCacheByUUID   Opcode = 19
	OpGetDefaultCache  Opcode = 20
	OpSetDefaultCache  Opcode = 21
	OpGetKDCOffset     Opcode = 22
	OpSetKDCOffset     Opcode = 23
	OpAddNTLMCred      Opcode = 24
	OpHaveNTLMCred     Opcode = 25
	OpDelNTLMCred      Opcode = 26
	OpDoNTLMAuth       Opcode = 27
	OpGetNTLMUserList  Opcode = 28

	// MIT extensions.
	OpMITExtensionBase Opcode = 13000
	OpGetCredList      Opcode = 13001
	OpReplace          Opcode = 13002
)

// ProtocolVersionMajor and ProtocolVersionMinor are the values MIT's
// client sends/expects in every request/response header.
const (
	ProtocolVersionMajor = 2
	ProtocolVersionMinor = 0
)

// Flag bits carried in the 32-bit flags word of RETRIEVE/REMOVE_CRED
// requests. These are Heimdal-numbered flags (per kcm.h), distinct from
// MIT's own KRB5_TC_*/KRB5_GC_* numeric values.
const (
	FlagGCCached uint32 = 1 << 0

	FlagTCDontMatchRealm   uint32 = 1 << 31
	FlagTCMatchKeytype     uint32 = 1 << 30
	FlagTCMatchSrvNameonly uint32 = 1 << 29
	FlagTCMatchFlagsExact  uint32 = 1 << 28
	FlagTCMatchFlags       uint32 = 1 << 27
	FlagTCMatchTimesExact  uint32 = 1 << 26
	FlagTCMatchTimes       uint32 = 1 << 25
	FlagTCMatchAuthdata    uint32 = 1 << 24
	FlagTCMatch2ndTkt      uint32 = 1 << 23
	FlagTCMatchIsSkey      uint32 = 1 << 22
)

// opcodesWithName lists the opcodes whose request body starts with a
// NUL-terminated cache-name string ahead of any other parameters (per
// the "(name, ...) -> ..." signatures documented in kcm.h). kcmex has
// exactly one cache, so handlers generally just skip over this field.
var opcodesWithName = map[Opcode]bool{
	OpInitialize:      true,
	OpDestroy:         true,
	OpStore:           true,
	OpRetrieve:        true,
	OpGetPrincipal:    true,
	OpGetCredUUIDList: true,
	OpGetCredByUUID:   true,
	OpRemoveCred:      true,
	OpSetDefaultCache: true,
	OpGetKDCOffset:    true,
	OpSetKDCOffset:    true,
	OpGetCredList:     true,
	OpReplace:         true,
}

// HasLeadingName reports whether op's request body starts with a
// NUL-terminated cache-name string.
func HasLeadingName(op Opcode) bool {
	return opcodesWithName[op]
}

// Supported reports whether kcmex implements op. Opcodes the MIT
// client never actually sends on the wire (per the comments in
// kcm.h) are left unimplemented and answered with KRB5_CC_NOSUPP.
func Supported(op Opcode) bool {
	switch op {
	case OpNoop, OpGenNew, OpInitialize, OpDestroy, OpStore, OpRetrieve,
		OpGetPrincipal, OpGetCredUUIDList, OpGetCredByUUID, OpGetCredList,
		OpRemoveCred, OpGetCacheUUIDList, OpGetCacheByUUID,
		OpGetDefaultCache, OpSetDefaultCache, OpGetKDCOffset, OpSetKDCOffset:
		return true
	default:
		return false
	}
}
