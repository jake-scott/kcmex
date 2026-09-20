package krb5c

/*
#include <krb5/krb5.h>
#include <stdlib.h>
*/
import "C"

import (
	"time"
	"unsafe"
)

// This file exists for the package's tests, which cannot use cgo
// directly (Go does not allow import "C" in _test.go files). It builds
// credentials and FILE ccaches out of thin air: structurally valid to
// libkrb5, but with a random session key and an opaque blob for the
// ticket, so nothing here could ever authenticate to anything. It is
// enough for exercising cache handling without a KDC.

// synthCredential returns the wire encoding of a made-up credential
// from client to server with the given lifetime and ticket flags.
func synthCredential(client, server string, start, end time.Time, flags int32) ([]byte, error) {
	k, err := newKctx()
	if err != nil {
		return nil, err
	}
	defer k.free()

	var creds C.krb5_creds
	if creds.client, err = k.parseName(client); err != nil {
		return nil, err
	}
	defer C.krb5_free_principal(k.ctx, creds.client)
	if creds.server, err = k.parseName(server); err != nil {
		return nil, err
	}
	defer C.krb5_free_principal(k.ctx, creds.server)

	if code := C.krb5_c_make_random_key(k.ctx, C.ENCTYPE_AES256_CTS_HMAC_SHA1_96, &creds.keyblock); code != 0 {
		return nil, newError(k.ctx, code)
	}
	defer C.krb5_free_keyblock_contents(k.ctx, &creds.keyblock)

	ticket := []byte("not-a-real-ticket:" + server)
	creds.ticket.data = (*C.char)(C.CBytes(ticket))
	creds.ticket.length = C.uint(len(ticket))
	defer C.free(unsafe.Pointer(creds.ticket.data))

	creds.times.authtime = C.krb5_timestamp(start.Unix())
	creds.times.starttime = C.krb5_timestamp(start.Unix())
	creds.times.endtime = C.krb5_timestamp(end.Unix())
	if flags&tktFlgRenewable != 0 {
		creds.times.renew_till = C.krb5_timestamp(end.Add(7 * 24 * time.Hour).Unix())
	}
	creds.ticket_flags = C.krb5_flags(flags)

	return k.marshalCreds(&creds)
}

// writeFileCcache creates a FILE ccache at path for principal, holding
// the given wire-format credentials.
func writeFileCcache(path, principal string, wires [][]byte) error {
	k, err := newKctx()
	if err != nil {
		return err
	}
	defer k.free()

	name := C.CString("FILE:" + path)
	defer C.free(unsafe.Pointer(name))
	var cc C.krb5_ccache
	if code := C.krb5_cc_resolve(k.ctx, name, &cc); code != 0 {
		return newError(k.ctx, code)
	}
	defer C.krb5_cc_close(k.ctx, cc)

	princ, err := k.parseName(principal)
	if err != nil {
		return err
	}
	defer C.krb5_free_principal(k.ctx, princ)
	if code := C.krb5_cc_initialize(k.ctx, cc, princ); code != 0 {
		return newError(k.ctx, code)
	}

	for _, wire := range wires {
		creds, err := k.unmarshalCreds(wire)
		if err != nil {
			return err
		}
		code := C.krb5_cc_store_cred(k.ctx, cc, creds)
		C.krb5_free_creds(k.ctx, creds)
		if code != 0 {
			return newError(k.ctx, code)
		}
	}
	return nil
}
