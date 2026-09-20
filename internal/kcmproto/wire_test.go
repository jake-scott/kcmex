package kcmproto

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func TestMessageRoundTrip(t *testing.T) {
	want := []byte{0x02, 0x00, 0x00, 0x07, 'h', 'i', 0}
	var buf bytes.Buffer
	if err := WriteMessage(&buf, want); err != nil {
		t.Fatalf("WriteMessage: %v", err)
	}
	got, err := ReadMessage(&buf)
	if err != nil {
		t.Fatalf("ReadMessage: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("got %x, want %x", got, want)
	}
}

func TestParseRequestHeader(t *testing.T) {
	body := []byte{2, 0, 0, 7, 'n', 'a', 'm', 'e', 0, 1, 2, 3}
	op, rest, err := ParseRequestHeader(body)
	if err != nil {
		t.Fatalf("ParseRequestHeader: %v", err)
	}
	if op != OpRetrieve {
		t.Fatalf("op = %d, want %d", op, OpRetrieve)
	}
	if !bytes.Equal(rest, body[4:]) {
		t.Fatalf("rest = %x, want %x", rest, body[4:])
	}
}

func TestWriteReplyFraming(t *testing.T) {
	// Per cc_kcm.c's kcmio_unix_socket_read + kcmio_call, a successful
	// reply is: length(4B BE, = 4+len(payload)), a zero transport word,
	// the real status code, then the payload.
	var buf bytes.Buffer
	payload := []byte("501\x00")
	if err := WriteReply(&buf, 0, payload); err != nil {
		t.Fatalf("WriteReply: %v", err)
	}
	got := buf.Bytes()
	want := []byte{
		0, 0, 0, 8, // length = 4 (status word) + 4 (payload)
		0, 0, 0, 0, // transport word, always 0
		0, 0, 0, 0, // real status code (success)
		'5', '0', '1', 0, // payload
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("got %x, want %x", got, want)
	}
}

func TestWriteReplyError(t *testing.T) {
	var code int32 = -1765328243 // KRB5_CC_NOTFOUND
	var buf bytes.Buffer
	if err := WriteReply(&buf, code, nil); err != nil {
		t.Fatalf("WriteReply: %v", err)
	}
	got := buf.Bytes()

	var codeBytes [4]byte
	binary.BigEndian.PutUint32(codeBytes[:], uint32(code))
	want := append([]byte{
		0, 0, 0, 4, // length = 4 (status word only, no payload)
		0, 0, 0, 0, // transport word
	}, codeBytes[:]...)
	if !bytes.Equal(got, want) {
		t.Fatalf("got %x, want %x", got, want)
	}
}

func TestPrincipalRoundTrip(t *testing.T) {
	want := Principal{
		Type:       1,
		Realm:      "EXAMPLE.COM",
		Components: []string{"host", "www.example.com"},
	}
	buf := MarshalPrincipal(want)
	got, n, err := UnmarshalPrincipal(buf)
	if err != nil {
		t.Fatalf("UnmarshalPrincipal: %v", err)
	}
	if n != len(buf) {
		t.Fatalf("consumed %d bytes, want %d", n, len(buf))
	}
	if got.Type != want.Type || got.Realm != want.Realm || len(got.Components) != len(want.Components) {
		t.Fatalf("got %+v, want %+v", got, want)
	}
	for i := range want.Components {
		if got.Components[i] != want.Components[i] {
			t.Fatalf("component %d: got %q, want %q", i, got.Components[i], want.Components[i])
		}
	}
}

func TestPrincipalUnparseName(t *testing.T) {
	p := Principal{Realm: "EXAMPLE.COM", Components: []string{"host", "www.example.com"}}
	if got, want := p.UnparseName(), "host/www.example.com@EXAMPLE.COM"; got != want {
		t.Fatalf("got %q, want %q", got, want)
	}

	// Components containing '/' or '@' must be escaped so the result can
	// be safely re-parsed by krb5_parse_name.
	p2 := Principal{Realm: "EXAMPLE.COM", Components: []string{"weird/name"}}
	if got, want := p2.UnparseName(), `weird\/name@EXAMPLE.COM`; got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestUUIDListRoundTrip(t *testing.T) {
	want := []UUID{{1, 2, 3}, {4, 5, 6}}
	buf := PutUUIDList(want)
	got, err := ReadUUIDList(buf)
	if err != nil {
		t.Fatalf("ReadUUIDList: %v", err)
	}
	if len(got) != len(want) {
		t.Fatalf("got %d uuids, want %d", len(got), len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("uuid %d: got %x, want %x", i, got[i], want[i])
		}
	}
}

// buildMcred hand-assembles bytes in the k5_marshal_mcred layout, mirroring
// what MIT's client actually sends for RETRIEVE/REMOVE_CRED, so
// UnmarshalMatchCredential can be tested without a live libkrb5 client.
func buildMcred(t *testing.T, server *Principal, endtime uint32) []byte {
	t.Helper()
	var header uint32
	buf := []byte{}
	if server != nil {
		header |= scServerPrincipal
	}
	buf = append(buf, PutUint32(header)...)
	if server != nil {
		buf = append(buf, MarshalPrincipal(*server)...)
	}
	// authtime, starttime, endtime, renew_till
	buf = append(buf, PutUint32(0)...)
	buf = append(buf, PutUint32(0)...)
	buf = append(buf, PutUint32(endtime)...)
	buf = append(buf, PutUint32(0)...)
	buf = append(buf, 0)               // is_skey
	buf = append(buf, PutUint32(0)...) // ticket_flags
	return buf
}

func TestUnmarshalMatchCredential(t *testing.T) {
	server := Principal{Type: 2, Realm: "EXAMPLE.COM", Components: []string{"host", "localhost"}}
	buf := buildMcred(t, &server, 12345)

	mc, err := UnmarshalMatchCredential(buf)
	if err != nil {
		t.Fatalf("UnmarshalMatchCredential: %v", err)
	}
	if mc.HasClient {
		t.Fatalf("HasClient = true, want false")
	}
	if !mc.HasServer {
		t.Fatalf("HasServer = false, want true")
	}
	if mc.Server.Realm != server.Realm || len(mc.Server.Components) != 2 {
		t.Fatalf("got server %+v, want %+v", mc.Server, server)
	}
	if mc.EndTime != 12345 {
		t.Fatalf("EndTime = %d, want 12345", mc.EndTime)
	}
	if mc.HasTicket || mc.HasSecondTicket || mc.HasSessionKey {
		t.Fatalf("unexpected optional field set: %+v", mc)
	}
}

func TestUnmarshalMatchCredentialNoServer(t *testing.T) {
	buf := buildMcred(t, nil, 0)
	mc, err := UnmarshalMatchCredential(buf)
	if err != nil {
		t.Fatalf("UnmarshalMatchCredential: %v", err)
	}
	if mc.HasServer {
		t.Fatalf("HasServer = true, want false")
	}
}
