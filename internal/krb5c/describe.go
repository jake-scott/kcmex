package krb5c

/*
#include <krb5/krb5.h>
*/
import "C"

import (
	"fmt"
	"strings"
	"time"

	"github.com/jake-scott/kcmex/internal/kcmproto"
)

// ErrorMessage returns libkrb5's own text for a krb5 error code as it
// would appear in a KCM reply (for example "Matching credential not
// found" for KRB5_CC_NOTFOUND), or "OK" for zero. It is intended for
// log output only.
func (c *Client) ErrorMessage(code int32) string {
	if code == 0 {
		return "OK"
	}
	k, err := c.acquire()
	if err != nil {
		return fmt.Sprintf("krb5 error %d", code)
	}
	defer c.release(k)
	msg := C.krb5_get_error_message(k.ctx, C.krb5_error_code(code))
	defer C.krb5_free_error_message(k.ctx, msg)
	return C.GoString(msg)
}

// CredentialSummary is the non-secret outline of one wire-format
// credential, as decoded for log output. The session key itself is
// never included; only its enctype is.
type CredentialSummary struct {
	Client, Server                          kcmproto.Principal
	Enctype                                 int32
	AuthTime, StartTime, EndTime, RenewTill int32
	IsSKey                                  bool
	TicketFlags                             uint32
	TicketLen                               int
}

// String renders the summary as a single "key=value ..." line.
func (s CredentialSummary) String() string {
	parts := []string{
		"client=" + s.Client.UnparseName(),
		"server=" + s.Server.UnparseName(),
		fmt.Sprintf("enctype=%d", s.Enctype),
		"authtime=" + kcmproto.FormatTimestamp(s.AuthTime),
		"starttime=" + kcmproto.FormatTimestamp(s.StartTime),
		"endtime=" + kcmproto.FormatTimestamp(s.EndTime),
		"renew_till=" + kcmproto.FormatTimestamp(s.RenewTill),
		fmt.Sprintf("is_skey=%t", s.IsSKey),
		fmt.Sprintf("ticket_flags=0x%08x", s.TicketFlags),
		fmt.Sprintf("ticket_len=%d", s.TicketLen),
	}
	return strings.Join(parts, " ")
}

// SummarizeCredential decodes a wire-format credential (as sent in a
// KCM_OP_STORE request) just far enough to describe it in a log line.
// Nothing is stored and no key material is copied out.
func (c *Client) SummarizeCredential(wire []byte) (CredentialSummary, error) {
	k, err := c.acquire()
	if err != nil {
		return CredentialSummary{}, err
	}
	defer c.release(k)
	creds, err := k.unmarshalCreds(wire)
	if err != nil {
		return CredentialSummary{}, err
	}
	defer C.krb5_free_creds(k.ctx, creds)
	return CredentialSummary{
		Client:      readPrincipal(creds.client),
		Server:      readPrincipal(creds.server),
		Enctype:     int32(creds.keyblock.enctype),
		AuthTime:    int32(creds.times.authtime),
		StartTime:   int32(creds.times.starttime),
		EndTime:     int32(creds.times.endtime),
		RenewTill:   int32(creds.times.renew_till),
		IsSKey:      creds.is_skey != 0,
		TicketFlags: uint32(creds.ticket_flags),
		TicketLen:   int(creds.ticket.length),
	}, nil
}

// withEndTime returns a copy of a wire-format credential whose end time
// has been replaced. Only the ccache metadata changes; the ticket itself
// is untouched. It exists for tests, which cannot use cgo directly, to
// manufacture a near-expiry entry.
func (c *Client) withEndTime(wire []byte, end time.Time) ([]byte, error) {
	k, err := c.acquire()
	if err != nil {
		return nil, err
	}
	defer c.release(k)
	creds, err := k.unmarshalCreds(wire)
	if err != nil {
		return nil, err
	}
	defer C.krb5_free_creds(k.ctx, creds)
	creds.times.endtime = C.krb5_timestamp(end.Unix())
	return k.marshalCreds(creds)
}
