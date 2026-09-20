package kcmproto

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

// ErrTruncated is returned when a wire structure is shorter than its
// declared/expected length.
var ErrTruncated = errors.New("kcmproto: truncated message")

// ReadMessage reads one length-prefixed KCM message (request or reply)
// from r: a 4-byte big-endian length, followed by that many bytes.
func ReadMessage(r io.Reader) ([]byte, error) {
	var lenBuf [4]byte
	if _, err := io.ReadFull(r, lenBuf[:]); err != nil {
		return nil, err
	}
	n := binary.BigEndian.Uint32(lenBuf[:])
	// Guard against a hostile/corrupt peer asking us to allocate something
	// absurd; real KCM messages are tiny (single tickets, short lists).
	const maxMessage = 1 << 20
	if n > maxMessage {
		return nil, fmt.Errorf("kcmproto: message length %d exceeds limit", n)
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(r, buf); err != nil {
		return nil, err
	}
	return buf, nil
}

// WriteMessage writes body as one length-prefixed KCM message.
func WriteMessage(w io.Writer, body []byte) error {
	var lenBuf [4]byte
	binary.BigEndian.PutUint32(lenBuf[:], uint32(len(body)))
	if _, err := w.Write(lenBuf[:]); err != nil {
		return err
	}
	_, err := w.Write(body)
	return err
}

// ParseRequestHeader splits a request message body into its opcode and
// the remaining opcode-specific bytes. Requests begin with a 1-byte
// major version, 1-byte minor version, and 16-bit big-endian opcode.
func ParseRequestHeader(body []byte) (op Opcode, rest []byte, err error) {
	if len(body) < 4 {
		return 0, nil, ErrTruncated
	}
	// The major/minor version bytes are not validated strictly: the MIT
	// client always sends 2.0, and rejecting on a future minor version
	// bump would be needlessly brittle.
	op = Opcode(binary.BigEndian.Uint16(body[2:4]))
	return op, body[4:], nil
}

// WriteReply writes one KCM reply to w.
//
// The MIT client's transport layer (kcmio_unix_socket_read in
// cc_kcm.c) reads a 4-byte big-endian length, then a 4-byte big-endian
// "transport" code, then exactly length bytes of body; if the
// transport code is nonzero it stops right there without reading a
// body at all. But the caller (kcmio_call) then treats the first 4
// bytes of that body as a second, logical status word of its own
// (read via k5_input_get_uint32_be) before handing the rest to each
// operation's own reply parser (e.g. kcmreq_get_name). So a
// successful reply genuinely needs two consecutive zero status words
// before the payload: length must cover the second status word plus
// the payload, not the payload alone. Verified empirically against a
// real klist/KCM exchange - sending only one status word makes the
// client misparse the payload's leading bytes as a bogus error code.
func WriteReply(w io.Writer, code int32, payload []byte) error {
	var lenBuf, transportBuf, codeBuf [4]byte
	binary.BigEndian.PutUint32(lenBuf[:], uint32(4+len(payload)))
	binary.BigEndian.PutUint32(codeBuf[:], uint32(code))
	if _, err := w.Write(lenBuf[:]); err != nil {
		return err
	}
	if _, err := w.Write(transportBuf[:]); err != nil { // always 0
		return err
	}
	if _, err := w.Write(codeBuf[:]); err != nil {
		return err
	}
	_, err := w.Write(payload)
	return err
}

// SplitCName splits a leading NUL-terminated cache-name string off the
// front of body, for opcodes where HasLeadingName is true.
func SplitCName(body []byte) (name string, rest []byte, err error) {
	i := bytes.IndexByte(body, 0)
	if i < 0 {
		return "", nil, ErrTruncated
	}
	return string(body[:i]), body[i+1:], nil
}

// PutCName appends s as a NUL-terminated string.
func PutCName(s string) []byte {
	out := make([]byte, len(s)+1)
	copy(out, s)
	return out
}

// ReadUint32 reads a 32-bit big-endian integer and returns the
// remaining bytes. Flags, time offsets, and lengths all use this
// encoding on the wire.
func ReadUint32(body []byte) (v uint32, rest []byte, err error) {
	if len(body) < 4 {
		return 0, nil, ErrTruncated
	}
	return binary.BigEndian.Uint32(body[:4]), body[4:], nil
}

// PutUint32 encodes v as 4 big-endian bytes.
func PutUint32(v uint32) []byte {
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], v)
	return b[:]
}

// UUID is a raw 16-byte KCM cache/credential identifier.
type UUID [16]byte

// ReadUUIDList decodes body as a sequence of 16-byte UUIDs. Per kcm.h,
// "UUID lists are not delimited, so nothing can come after them" -
// i.e. a UUID list always consumes the rest of the message.
func ReadUUIDList(body []byte) ([]UUID, error) {
	if len(body)%16 != 0 {
		return nil, fmt.Errorf("kcmproto: UUID list length %d not a multiple of 16", len(body))
	}
	out := make([]UUID, 0, len(body)/16)
	for i := 0; i < len(body); i += 16 {
		var u UUID
		copy(u[:], body[i:i+16])
		out = append(out, u)
	}
	return out, nil
}

// PutUUIDList encodes uuids back-to-back with no delimiters.
func PutUUIDList(uuids []UUID) []byte {
	out := make([]byte, 0, len(uuids)*16)
	for _, u := range uuids {
		out = append(out, u[:]...)
	}
	return out
}
