package kcmproto

import (
	"strings"
	"testing"
)

func TestOpcodeString(t *testing.T) {
	cases := map[Opcode]string{
		OpNoop:         "NOOP",
		OpRetrieve:     "RETRIEVE",
		OpGetCredList:  "GET_CRED_LIST",
		OpReplace:      "REPLACE",
		Opcode(999):    "OPCODE(999)",
		Opcode(0xffff): "OPCODE(65535)",
	}
	for op, want := range cases {
		if got := op.String(); got != want {
			t.Errorf("Opcode(%d).String() = %q, want %q", uint16(op), got, want)
		}
	}
}

func TestMatchFlagsString(t *testing.T) {
	cases := map[uint32]string{
		0:                               "0",
		FlagGCCached:                    "GC_CACHED",
		FlagTCMatchTimes | FlagGCCached: "TC_MATCH_TIMES|GC_CACHED",
		FlagTCDontMatchRealm | 1<<5:     "TC_DONT_MATCH_REALM|0x00000020",
		FlagTCMatchKeytype | FlagTCMatchTimesExact: "TC_MATCH_KEYTYPE|TC_MATCH_TIMES_EXACT",
	}
	for flags, want := range cases {
		if got := MatchFlagsString(flags); got != want {
			t.Errorf("MatchFlagsString(%#x) = %q, want %q", flags, got, want)
		}
	}
}

func TestUUIDString(t *testing.T) {
	var u UUID
	for i := range u {
		u[i] = byte(i)
	}
	want := "000102030405060708090a0b0c0d0e0f"
	if got := u.String(); got != want {
		t.Fatalf("UUID.String() = %q, want %q", got, want)
	}
}

func TestFormatTimestamp(t *testing.T) {
	if got := FormatTimestamp(0); got != "0" {
		t.Errorf("FormatTimestamp(0) = %q, want \"0\"", got)
	}
	if got, want := FormatTimestamp(1_700_000_000), "2023-11-14T22:13:20Z"; got != want {
		t.Errorf("FormatTimestamp(1700000000) = %q, want %q", got, want)
	}
	// Timestamps past 2038 arrive as a wrapped-negative int32 and must
	// still render as the intended (unsigned) date.
	past2038 := uint32(2_200_000_000)
	if got, want := FormatTimestamp(int32(past2038)), "2039-09-18T23:06:40Z"; got != want {
		t.Errorf("FormatTimestamp(2200000000) = %q, want %q", got, want)
	}
}

func TestMatchCredentialString(t *testing.T) {
	mc := MatchCredential{
		HasServer: true,
		Server:    Principal{Realm: "EXAMPLE.COM", Components: []string{"HTTP", "web.example.com"}},
		EndTime:   1_700_000_000,
	}
	got := mc.String()
	for _, want := range []string{"server=HTTP/web.example.com@EXAMPLE.COM", "endtime=2023-11-14T22:13:20Z"} {
		if !strings.Contains(got, want) {
			t.Errorf("MatchCredential.String() = %q, missing %q", got, want)
		}
	}
	for _, unwanted := range []string{"client=", "enctype=", "authtime=", "ticket_len=", "is_skey"} {
		if strings.Contains(got, unwanted) {
			t.Errorf("MatchCredential.String() = %q, should not contain %q", got, unwanted)
		}
	}

	mc.HasSessionKey = true
	mc.KeyType = 18
	mc.KeyData = []byte("supersecretkey!!")
	got = mc.String()
	if !strings.Contains(got, "enctype=18 key_len=16") {
		t.Errorf("MatchCredential.String() = %q, missing enctype/key_len", got)
	}
	if strings.Contains(got, "supersecret") {
		t.Errorf("MatchCredential.String() = %q leaks key material", got)
	}

	if got := (MatchCredential{}).String(); got != "(empty)" {
		t.Errorf("empty MatchCredential.String() = %q, want \"(empty)\"", got)
	}
}
