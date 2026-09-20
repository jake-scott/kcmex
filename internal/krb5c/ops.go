package krb5c

/*
#include <krb5/krb5.h>
#include <stdlib.h>
*/
import "C"

import (
	"fmt"
	"time"

	"github.com/jake-scott/kcmex/internal/kcmproto"
)

// Entry describes one credential currently held in the daemon's working
// cache, as needed to answer KCM listing operations.
type Entry struct {
	UUID   kcmproto.UUID
	Server kcmproto.Principal
	Wire   []byte // the credential, already in KCM wire (v4 ccache) format
}

// forEachEntry sequentially walks the working cache, skipping ccache
// "config" pseudo-entries (used internally by libkrb5 for things like
// FAST/PKINIT state, never real tickets). For each real entry it
// marshals the credential to wire format, derives its UUID, and invokes
// fn; fn returns true to stop early. cred is only valid for the
// duration of the fn call.
func (c *Client) forEachEntry(fn func(cred *C.krb5_creds, wire []byte, uuid kcmproto.UUID) bool) error {
	var cursor C.krb5_cc_cursor
	if code := C.krb5_cc_start_seq_get(c.ctx, c.cc, &cursor); code != 0 {
		return newError(c.ctx, code)
	}
	for {
		var cred C.krb5_creds
		code := C.krb5_cc_next_cred(c.ctx, c.cc, &cursor, &cred)
		if int32(code) == CCEnd {
			break
		}
		if code != 0 {
			C.krb5_cc_end_seq_get(c.ctx, c.cc, &cursor)
			return newError(c.ctx, code)
		}
		if C.krb5_is_config_principal(c.ctx, cred.server) != 0 {
			C.krb5_free_cred_contents(c.ctx, &cred)
			continue
		}
		wire, err := c.marshalCreds(&cred)
		if err != nil {
			C.krb5_free_cred_contents(c.ctx, &cred)
			C.krb5_cc_end_seq_get(c.ctx, c.cc, &cursor)
			return err
		}
		stop := fn(&cred, wire, uuidOf(wire))
		C.krb5_free_cred_contents(c.ctx, &cred)
		if stop {
			break
		}
	}
	return newError(c.ctx, C.krb5_cc_end_seq_get(c.ctx, c.cc, &cursor))
}

// DefaultPrincipal returns the working cache's client principal (the
// identity from the TGT it was seeded with, or set by a later
// Initialize call).
func (c *Client) DefaultPrincipal() (kcmproto.Principal, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	var princ C.krb5_principal
	if code := C.krb5_cc_get_principal(c.ctx, c.cc, &princ); code != 0 {
		return kcmproto.Principal{}, newError(c.ctx, code)
	}
	defer C.krb5_free_principal(c.ctx, princ)
	return readPrincipal(princ), nil
}

// ListEntries returns every real credential currently in the working
// cache (the TGT plus any acquired or pre-existing service tickets).
func (c *Client) ListEntries() ([]Entry, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.maintain(time.Now())
	var entries []Entry
	var redErr error
	err := c.forEachEntry(func(cred *C.krb5_creds, wire []byte, uuid kcmproto.UUID) bool {
		server := readPrincipal(cred.server)
		w := wire
		if isTGTServer(server) {
			// Expose the TGT's existence and metadata, but strip the
			// session key so a listing client cannot use it. The UUID is
			// still derived from the true credential, so GET_CRED_BY_UUID
			// stays consistent with this list.
			if w, redErr = c.marshalTGTForListing(cred); redErr != nil {
				return true
			}
		}
		entries = append(entries, Entry{
			UUID:   uuid,
			Server: server,
			Wire:   append([]byte(nil), w...),
		})
		return false
	})
	if redErr != nil {
		return nil, redErr
	}
	return entries, err
}

// EntryByUUID returns the single entry matching uuid, if present.
func (c *Client) EntryByUUID(uuid kcmproto.UUID) (Entry, bool, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.maintain(time.Now())
	var found Entry
	ok := false
	var redErr error
	err := c.forEachEntry(func(cred *C.krb5_creds, wire []byte, u kcmproto.UUID) bool {
		if u != uuid {
			return false
		}
		server := readPrincipal(cred.server)
		w := wire
		if isTGTServer(server) {
			// See ListEntries: the TGT is listable but its session key is
			// withheld from the returned credential.
			if w, redErr = c.marshalTGTForListing(cred); redErr != nil {
				return true
			}
		}
		found = Entry{UUID: u, Server: server, Wire: append([]byte(nil), w...)}
		ok = true
		return true
	})
	if redErr != nil {
		return Entry{}, false, redErr
	}
	return found, ok, err
}

// RemoveByUUID removes the entry matching uuid, if present. It reports
// whether an entry was found and removed.
func (c *Client) RemoveByUUID(uuid kcmproto.UUID) (bool, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	var wire []byte
	found := false
	err := c.forEachEntry(func(cred *C.krb5_creds, w []byte, u kcmproto.UUID) bool {
		if u != uuid {
			return false
		}
		wire = append([]byte(nil), w...)
		found = true
		return true
	})
	if err != nil || !found {
		return false, err
	}

	// Re-decode the found entry into a fresh krb5_creds to use as the
	// match template for removal, rather than mutating the cache while
	// a sequential-read cursor over it might still be settling.
	creds, err := c.unmarshalCreds(wire)
	if err != nil {
		return false, err
	}
	defer C.krb5_free_creds(c.ctx, creds)
	if code := C.krb5_cc_remove_cred(c.ctx, c.cc, 0, creds); code != 0 {
		return false, newError(c.ctx, code)
	}
	return true, nil
}

// buildMatchTemplate constructs a krb5_creds template from a decoded
// KCM match-credential (see kcmproto.MatchCredential - a distinct,
// sparser wire format from the one krb5_unmarshal_credentials reads),
// for use as the in_creds argument to krb5_get_credentials or
// krb5_cc_remove_cred. The returned cleanup function must always be
// called (e.g. via defer) once the template is no longer needed,
// whether or not err is set - it releases whatever was allocated
// before the error occurred.
func (c *Client) buildMatchTemplate(mc kcmproto.MatchCredential) (creds C.krb5_creds, cleanup func(), err error) {
	var toFree []func()
	cleanup = func() {
		for i := len(toFree) - 1; i >= 0; i-- {
			toFree[i]()
		}
	}

	if mc.HasClient {
		p, perr := c.buildPrincipal(mc.Client)
		if perr != nil {
			return creds, cleanup, fmt.Errorf("client principal: %w", perr)
		}
		creds.client = p
		toFree = append(toFree, func() { C.krb5_free_principal(c.ctx, p) })
	} else {
		// The MIT client typically omits the client principal in a
		// match-credential, relying on it defaulting to the cache's own
		// identity - which is what every credential in this daemon's
		// single working cache shares anyway.
		var p C.krb5_principal
		if code := C.krb5_cc_get_principal(c.ctx, c.cc, &p); code != 0 {
			return creds, cleanup, newError(c.ctx, code)
		}
		creds.client = p
		toFree = append(toFree, func() { C.krb5_free_principal(c.ctx, p) })
	}

	if !mc.HasServer {
		return creds, cleanup, fmt.Errorf("match-credential has no server principal")
	}
	p, perr := c.buildPrincipal(mc.Server)
	if perr != nil {
		return creds, cleanup, fmt.Errorf("server principal: %w", perr)
	}
	creds.server = p
	toFree = append(toFree, func() { C.krb5_free_principal(c.ctx, p) })

	if mc.HasSessionKey {
		creds.keyblock.enctype = C.krb5_enctype(mc.KeyType)
	}
	// The match-credential's times are deliberately NOT copied. The MIT
	// client fills mcred.times.endtime with its current time, meaning
	// "must still be valid now". But krb5_get_credentials treats
	// in_creds.times.endtime as the *requested* end time: on a cache
	// miss it becomes the TGS-REQ's 'till', and the KDC issues a ticket
	// ending at min(till, TGT end, max_life) - i.e. one that expires the
	// moment it is issued. Leaving it zero makes 'till' default to the
	// TGT's end time, so service tickets inherit the TGT's remaining
	// lifetime. Validity is enforced separately: libkrb5's own lookup
	// skips expired entries, and sweep() evicts near-expiry ones.
	if mc.IsSKey {
		creds.is_skey = 1
	}
	if mc.HasSecondTicket && len(mc.SecondTicket) > 0 {
		ptr := C.CBytes(mc.SecondTicket)
		creds.second_ticket.data = (*C.char)(ptr)
		creds.second_ticket.length = C.uint(len(mc.SecondTicket))
		toFree = append(toFree, func() { C.free(ptr) })
	}

	// Addresses and authdata match hints are not currently forwarded (see
	// kcmproto.MatchCredential); krb5_get_credentials/krb5_cc_remove_cred
	// simply won't match on those fields for now.

	return creds, cleanup, nil
}

// Retrieve is the core of KCM_OP_RETRIEVE: given the decoded
// match-credential (at minimum a target server principal), it resolves
// a service ticket via krb5_get_credentials against the working cache.
//
// Deliberately, options is always 0: KRB5_GC_CACHED is never passed,
// regardless of whether the wire request carried KCM_GC_CACHED. That is
// what makes krb5_get_credentials free to perform a real TGS-REQ on a
// cache miss instead of just reporting "not found" - without it, the
// MIT client would see a cache-miss on a "cache only" retrieve and try
// to obtain the ticket itself from its own local TGT, which does not
// exist (the only TGT lives inside this daemon).
func (c *Client) Retrieve(mc kcmproto.MatchCredential) ([]byte, error) {
	// The TGT is listable but never retrievable: a client that could pull
	// it (or a foreign/cross-realm TGT) would hold the session key needed
	// to drive its own TGS-REQ, defeating the point of the daemon holding
	// the TGT. Service tickets are unaffected - those are obtained via the
	// internal krb5_get_credentials call below, not by the client fetching
	// the TGT.
	if mc.HasServer && isTGTServer(mc.Server) {
		return nil, &Error{
			Code:    FCCPerm,
			Message: "retrieval of the ticket-granting ticket is not permitted",
		}
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	// Renew/reload the TGT if needed and evict stale service tickets
	// first, so the lookup below misses on anything too close to expiry
	// and fetches a fresh ticket instead of handing back the old one.
	now := time.Now()
	c.maintain(now)
	if err := c.tgtError(now); err != nil {
		return nil, err
	}

	inCreds, cleanup, err := c.buildMatchTemplate(mc)
	defer cleanup()
	if err != nil {
		return nil, err
	}

	// The MIT client looks up its ccache "config" pseudo-entries
	// (krbtgt/X-CACHECONF:/...) through RETRIEVE as well. Those are not
	// tickets and the working cache never holds any, so answer not-found
	// directly rather than letting krb5_get_credentials ask the KDC for
	// a principal that cannot exist.
	if C.krb5_is_config_principal(c.ctx, inCreds.server) != 0 {
		return nil, &Error{Code: CCNotFound, Message: "Matching credential not found"}
	}

	var outCreds *C.krb5_creds
	code := C.krb5_get_credentials(c.ctx, 0, c.cc, &inCreds, &outCreds)
	if code != 0 {
		return nil, newError(c.ctx, code)
	}
	defer C.krb5_free_creds(c.ctx, outCreds)

	return c.marshalCreds(outCreds)
}

// RemoveMatching asks libkrb5's own krb5_cc_remove_cred to find and
// remove the entry matching the decoded KCM_OP_REMOVE_CRED
// match-credential.
//
// Known limitation: the match flags accompanying the request use
// Heimdal's KCM_TC_* numbering on the wire, which does not line up
// bit-for-bit with MIT's own KRB5_TC_* numbering that
// krb5_cc_remove_cred expects; kcmex does not currently translate
// between the two and always passes 0 (match on the principal fields
// present in the decoded template). REMOVE_CRED is rarely exercised in
// practice (kdestroy uses KCM_OP_DESTROY instead), so this is an
// accepted v1 simplification rather than a correctness requirement.
func (c *Client) RemoveMatching(mc kcmproto.MatchCredential) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	inCreds, cleanup, err := c.buildMatchTemplate(mc)
	defer cleanup()
	if err != nil {
		return err
	}
	if code := C.krb5_cc_remove_cred(c.ctx, c.cc, 0, &inCreds); code != 0 {
		return newError(c.ctx, code)
	}
	return nil
}

// Store decodes credWire and stores it into the working cache, for
// KCM_OP_STORE. A stored ticket-granting ticket for the cache's own
// principal replaces the daemon's TGT (this is what "kinit" into the
// KCM: cache does after INITIALIZE), and is held under the same rules
// as one loaded from the source file.
func (c *Client) Store(credWire []byte) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	creds, err := c.unmarshalCreds(credWire)
	if err != nil {
		return err
	}
	defer C.krb5_free_creds(c.ctx, creds)

	client, server := readPrincipal(creds.client), readPrincipal(creds.server)
	if isLocalTGT(client, server) {
		var princ C.krb5_principal
		if code := C.krb5_cc_get_principal(c.ctx, c.cc, &princ); code != 0 {
			return newError(c.ctx, code)
		}
		mine := readPrincipal(princ).UnparseName() == client.UnparseName()
		C.krb5_free_principal(c.ctx, princ)
		if mine {
			info, err := c.tgtInfoFrom(creds)
			if err != nil {
				return err
			}
			if err := c.setTGT(creds, info); err != nil {
				return err
			}
			c.log.Info("adopted a stored ticket-granting ticket", "principal", client.UnparseName(),
				"expires", info.endTime, "renew_until", info.renewTill)
			return nil
		}
	}
	if code := C.krb5_cc_store_cred(c.ctx, c.cc, creds); code != 0 {
		return newError(c.ctx, code)
	}
	return nil
}

// Initialize re-initializes the working cache for principal p, for
// KCM_OP_INITIALIZE. Like a real ccache, this discards any existing
// entries.
func (c *Client) Initialize(p kcmproto.Principal) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	princ, err := c.buildPrincipal(p)
	if err != nil {
		return err
	}
	defer C.krb5_free_principal(c.ctx, princ)
	if code := C.krb5_cc_initialize(c.ctx, c.cc, princ); code != 0 {
		return newError(c.ctx, code)
	}
	// The TGT went with the rest of the entries. A later STORE of a TGT
	// (kinit into the KCM: cache) or a changed source ccache brings one
	// back.
	c.tgt = nil
	c.resetRenewBackoff()
	return nil
}
