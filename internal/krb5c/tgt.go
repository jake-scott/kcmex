package krb5c

/*
#include <krb5/krb5.h>
#include <stdlib.h>
*/
import "C"

import (
	"context"
	"errors"
	"fmt"
	"time"
	"unsafe"
)

// This file is the daemon's credential-lifetime management: keeping
// the TGT alive (renewal, or adopting a newer TGT from the source
// ccache after a fresh kinit), and keeping near-expiry service tickets
// out of the working cache so clients never receive one.

// tgtInfoFrom captures a library credential as the daemon's TGT record.
func (k *kctx) tgtInfoFrom(cred *C.krb5_creds) (*tgtInfo, error) {
	wire, err := k.marshalCreds(cred)
	if err != nil {
		return nil, err
	}
	return &tgtInfo{
		wire:      wire,
		client:    readPrincipal(cred.client),
		server:    readPrincipal(cred.server),
		flags:     int32(cred.ticket_flags),
		authTime:  krbTime(cred.times.authtime),
		startTime: krbTime(cred.times.starttime),
		endTime:   krbTime(cred.times.endtime),
		renewTill: krbTime(cred.times.renew_till),
	}, nil
}

// storeTGT stores the TGT into the working cache with
// TKT_FLG_RENEWABLE cleared on the cached copy (the ticket itself is
// untouched; ticket_flags is client-side bookkeeping).
//
// krb5_get_credentials derives the KDC options of every TGS-REQ it
// sends from the cached TGT's ticket_flags, and offers no way to
// override them. With the flag present, every service ticket the KDC
// issued would be renewable, and a renewable service ticket can be
// renewed by whoever holds it and its session key, without a TGT,
// until its renew_till - letting a client extend its own access to a
// service for days without going through the daemon. Clearing the flag
// on the cached copy makes libkrb5 ask for non-renewable service
// tickets. Renewal of the TGT itself uses the real credential kept in
// tgtInfo.wire, so nothing is lost.
func (k *kctx) storeTGT(cred *C.krb5_creds) error {
	saved := cred.ticket_flags
	cred.ticket_flags = saved &^ C.krb5_flags(C.TKT_FLG_RENEWABLE)
	code := C.krb5_cc_store_cred(k.ctx, k.cc, cred)
	cred.ticket_flags = saved
	return newError(k.ctx, code)
}

// removeCredExact removes the working-cache entry whose principals and
// times exactly match wire (a credential previously marshalled from the
// cache). Missing entries are not an error.
func (k *kctx) removeCredExact(wire []byte) error {
	creds, err := k.unmarshalCreds(wire)
	if err != nil {
		return err
	}
	defer C.krb5_free_creds(k.ctx, creds)
	code := C.krb5_cc_remove_cred(k.ctx, k.cc, C.krb5_flags(C.KRB5_TC_MATCH_TIMES_EXACT), creds)
	if int32(code) == CCNotFound {
		return nil
	}
	return newError(k.ctx, code)
}

// setTGT installs info as the daemon's TGT: the previous TGT entry (if
// any) is removed from the working cache and info's credential stored
// in its place. The caller holds c.mu for writing, since between the
// two steps the cache has no TGT at all.
func (c *Client) setTGT(k *kctx, info *tgtInfo) error {
	creds, err := k.unmarshalCreds(info.wire)
	if err != nil {
		return err
	}
	defer C.krb5_free_creds(k.ctx, creds)
	if c.tgt != nil {
		if err := k.removeCredExact(c.tgt.wire); err != nil {
			return fmt.Errorf("removing previous TGT: %w", err)
		}
	}
	if err := k.storeTGT(creds); err != nil {
		return err
	}
	c.tgt = info
	c.resetRenewBackoff()
	return nil
}

// tgtError is the reply for a RETRIEVE that cannot be served because
// there is no valid TGT to drive a TGS-REQ. KRB5KRB_AP_ERR_TKT_EXPIRED
// is what a client sees from an ordinary expired ccache, and the MIT
// client stops on it rather than trying to obtain the ticket itself.
// The caller holds c.mu.
func (c *Client) tgtError(now time.Time) error {
	if c.tgt == nil {
		return &Error{Code: TktExpired, Message: "no ticket-granting ticket is available; run kinit"}
	}
	if c.tgt.expired(now) {
		return &Error{Code: TktExpired, Message: "the ticket-granting ticket has expired; run kinit"}
	}
	return nil
}

// maintain brings the working cache up to date with respect to the
// clock: adopts a newer TGT from the source ccache if the held one is
// due for renewal, close to expiry or missing; renews the TGT when due;
// and evicts service tickets that are expired or too close to expiry
// to hand out. It runs at the start of every cache-reading operation
// and from the background loop.
//
// The caller holds no lock and lends its context k. Whether anything
// needs doing is decided under the read lock first, so the common case
// (nothing due) never blocks behind, or holds up, concurrent requests;
// only an actual reload takes the write lock, and only for as long as
// the file read takes.
func (c *Client) maintain(k *kctx, now time.Time) {
	c.mu.RLock()
	reload := c.tgtNeedsAttention(now) && now.Sub(c.lastFileCheck) >= fileCheckInterval
	renew := c.renewWanted(now)
	c.mu.RUnlock()

	if reload {
		c.mu.Lock()
		if c.tgtNeedsAttention(now) {
			c.loadNewerTGT(k, now)
		}
		renew = c.renewWanted(now)
		c.mu.Unlock()
	}
	if renew {
		if err := c.renewTGT(k, now); err != nil && !errors.Is(err, errRenewBusy) {
			c.mu.RLock()
			expires, retry := time.Time{}, c.renewBackoff
			if c.tgt != nil {
				expires = c.tgt.endTime
			}
			c.mu.RUnlock()
			c.log.Warn("could not renew the ticket-granting ticket", "error", err,
				"expires", expires, "retry_in", retry)
		}
	}
	c.sweep(k, now)
}

// tgtNeedsAttention reports whether the source ccache is worth
// consulting for a newer TGT. The caller holds c.mu.
func (c *Client) tgtNeedsAttention(now time.Time) bool {
	return c.tgt == nil || c.tgt.renewDue(now) || c.tgt.remaining(now) < c.minLife
}

// renewWanted reports whether a renewal should be started now. The
// caller holds c.mu.
func (c *Client) renewWanted(now time.Time) bool {
	return c.tgt != nil && c.tgt.renewDue(now) && !now.Before(c.renewRetryAt) && !c.renewing
}

// errRenewBusy is returned by renewTGT when another renewal is already
// in flight; the caller simply waits for that one.
var errRenewBusy = errors.New("a renewal is already in progress")

// renewTGT asks the KDC to renew the TGT and installs the result. The
// KDC exchange runs without holding c.mu, so requests keep flowing
// while the KDC is slow or unreachable; only the final swap takes the
// write lock. At most one renewal runs at a time (see c.renewing), and
// the result is dropped if the TGT was replaced meanwhile by a fresh
// kinit or an INITIALIZE, rather than resurrecting the old identity.
// The caller holds no lock.
func (c *Client) renewTGT(k *kctx, now time.Time) error {
	c.mu.Lock()
	if c.renewing {
		c.mu.Unlock()
		return errRenewBusy
	}
	started := c.tgt
	if started == nil {
		c.mu.Unlock()
		return errors.New("no ticket-granting ticket to renew")
	}
	c.renewing = true
	c.mu.Unlock()

	info, err := k.renewExchange(started.wire)

	c.mu.Lock()
	defer c.mu.Unlock()
	c.renewing = false
	if c.tgt != started {
		c.log.Debug("discarding renewal result: the ticket-granting ticket was replaced meanwhile")
		return nil
	}
	if err != nil {
		c.noteRenewFailure(now)
		return err
	}
	if err := c.setTGT(k, info); err != nil {
		c.noteRenewFailure(now)
		return err
	}
	c.log.Info("renewed the ticket-granting ticket",
		"principal", info.client.UnparseName(),
		"previous_expiry", started.endTime, "expires", info.endTime, "renew_until", info.renewTill)
	return nil
}

// renewExchange performs the renewal round trip for the TGT encoded in
// wire and returns the renewed credential.
//
// It is driven by krb5_get_renewed_creds against a scratch MEMORY:
// cache holding the real TGT (real flags, so the renewed ticket is
// itself renewable), not the working cache whose copy has the
// renewable flag cleared. The scratch cache is process-global like any
// MEMORY: cache, which is fine because renewals never overlap.
func (k *kctx) renewExchange(wire []byte) (*tgtInfo, error) {
	tgtCreds, err := k.unmarshalCreds(wire)
	if err != nil {
		return nil, err
	}
	defer C.krb5_free_creds(k.ctx, tgtCreds)

	name := C.CString("MEMORY:kcmex-renew")
	defer C.free(unsafe.Pointer(name))
	var tmp C.krb5_ccache
	if code := C.krb5_cc_resolve(k.ctx, name, &tmp); code != 0 {
		return nil, newError(k.ctx, code)
	}
	defer C.krb5_cc_destroy(k.ctx, tmp)
	if code := C.krb5_cc_initialize(k.ctx, tmp, tgtCreds.client); code != 0 {
		return nil, newError(k.ctx, code)
	}
	if code := C.krb5_cc_store_cred(k.ctx, tmp, tgtCreds); code != 0 {
		return nil, newError(k.ctx, code)
	}

	var renewed C.krb5_creds
	if code := C.krb5_get_renewed_creds(k.ctx, &renewed, tgtCreds.client, tmp, nil); code != 0 {
		return nil, newError(k.ctx, code)
	}
	defer C.krb5_free_cred_contents(k.ctx, &renewed)

	return k.tgtInfoFrom(&renewed)
}

// loadNewerTGT reads the source ccache and adopts its contents if they
// hold an unexpired TGT that outlives the one held (or if none is
// held). The file is not watched; this runs only when the held TGT
// needs attention, and at most once per fileCheckInterval. The caller
// holds c.mu for writing: adopting re-initialises the working cache
// and reloads it, and nothing may observe it in between.
func (c *Client) loadNewerTGT(k *kctx, now time.Time) {
	if now.Sub(c.lastFileCheck) < fileCheckInterval {
		return
	}
	c.lastFileCheck = now

	if c.ownerUID >= 0 {
		uid, err := fileOwner(c.srcPath)
		if err != nil {
			c.log.Debug("source ccache not readable", "ccache", c.srcPath, "error", err)
			return
		}
		if uid >= 0 && uid != c.ownerUID {
			c.log.Warn("ignoring source ccache: wrong owner", "ccache", c.srcPath, "uid", uid, "expected_uid", c.ownerUID)
			return
		}
	}

	name := C.CString("FILE:" + c.srcPath)
	defer C.free(unsafe.Pointer(name))
	var src C.krb5_ccache
	if code := C.krb5_cc_resolve(k.ctx, name, &src); code != 0 {
		c.log.Warn("ignoring source ccache: cannot open", "ccache", c.srcPath, "error", newError(k.ctx, code))
		return
	}
	defer C.krb5_cc_close(k.ctx, src)

	var princ C.krb5_principal
	if code := C.krb5_cc_get_principal(k.ctx, src, &princ); code != 0 {
		c.log.Debug("ignoring source ccache: no default principal", "ccache", c.srcPath, "error", newError(k.ctx, code))
		return
	}
	defer C.krb5_free_principal(k.ctx, princ)

	peek, err := k.peekTGT(src)
	if err != nil {
		c.log.Warn("ignoring source ccache: unreadable", "ccache", c.srcPath, "error", err)
		return
	}
	if peek == nil {
		c.log.Debug("source ccache holds no ticket-granting ticket", "ccache", c.srcPath)
		return
	}
	if peek.expired(now) {
		c.log.Debug("source ccache ticket-granting ticket has expired", "ccache", c.srcPath, "expires", peek.endTime)
		return
	}
	if c.tgt != nil && !peek.endTime.After(c.tgt.endTime) {
		c.log.Debug("source ccache ticket-granting ticket is not newer than the one held",
			"file_expires", peek.endTime, "held_expires", c.tgt.endTime)
		return
	}

	// Adopt the file: this is a new login session, so start the working
	// cache afresh (dropping service tickets obtained under the old TGT;
	// they are cheap to re-fetch).
	if code := C.krb5_cc_initialize(k.ctx, k.cc, princ); code != 0 {
		c.log.Error("reinitialising working cache failed", "error", newError(k.ctx, code))
		return
	}
	c.tgt = nil
	tgt, err := c.loadFrom(k, src, now)
	if err != nil {
		c.log.Error("reloading source ccache failed", "ccache", c.srcPath, "error", err)
		return
	}
	c.tgt = tgt
	c.resetRenewBackoff()
	c.log.Info("loaded a newer ticket-granting ticket from the source ccache", "ccache", c.srcPath,
		"principal", tgt.client.UnparseName(), "expires", tgt.endTime, "renew_until", tgt.renewTill)
}

// peekTGT scans src for its local TGT without storing anything.
func (k *kctx) peekTGT(src C.krb5_ccache) (*tgtInfo, error) {
	var found *tgtInfo
	var cursor C.krb5_cc_cursor
	if code := C.krb5_cc_start_seq_get(k.ctx, src, &cursor); code != 0 {
		return nil, newError(k.ctx, code)
	}
	for found == nil {
		var cred C.krb5_creds
		code := C.krb5_cc_next_cred(k.ctx, src, &cursor, &cred)
		if int32(code) == CCEnd {
			break
		}
		if code != 0 {
			C.krb5_cc_end_seq_get(k.ctx, src, &cursor)
			return nil, newError(k.ctx, code)
		}
		if C.krb5_is_config_principal(k.ctx, cred.server) == 0 &&
			isLocalTGT(readPrincipal(cred.client), readPrincipal(cred.server)) {
			info, err := k.tgtInfoFrom(&cred)
			if err != nil {
				C.krb5_free_cred_contents(k.ctx, &cred)
				C.krb5_cc_end_seq_get(k.ctx, src, &cursor)
				return nil, err
			}
			found = info
		}
		C.krb5_free_cred_contents(k.ctx, &cred)
	}
	return found, newError(k.ctx, C.krb5_cc_end_seq_get(k.ctx, src, &cursor))
}

// sweep evicts service tickets (anything but the local TGT) that have
// expired, or that have less than minLife left while the TGT outlives
// them, so that the next request for that service misses the cache and
// krb5_get_credentials fetches a fresh ticket. A ticket that is short
// only because the TGT itself is about to expire is kept: re-fetching
// it could not yield a longer one.
//
// libkrb5's own lookup already skips expired entries but not
// near-expiry ones, which is why the eviction is needed. It also keeps
// listings (klist, GSSAPI's cache scan) free of stale entries.
//
// The caller holds no lock; sweep takes the read lock itself. Each
// eviction is a single libkrb5 operation the cache serialises
// internally, and two sweeps racing to evict the same entry is
// harmless (the loser sees not-found), so the write lock is not needed.
func (c *Client) sweep(k *kctx, now time.Time) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	var stale [][]byte
	var cursor C.krb5_cc_cursor
	if code := C.krb5_cc_start_seq_get(k.ctx, k.cc, &cursor); code != 0 {
		return
	}
	for {
		var cred C.krb5_creds
		code := C.krb5_cc_next_cred(k.ctx, k.cc, &cursor, &cred)
		if code != 0 {
			break
		}
		if C.krb5_is_config_principal(k.ctx, cred.server) == 0 {
			client, server := readPrincipal(cred.client), readPrincipal(cred.server)
			end := krbTime(cred.times.endtime)
			left := end.Sub(now)
			evict := left <= 0 ||
				(left < c.minLife && c.tgt != nil && c.tgt.endTime.After(end))
			if evict && !isLocalTGT(client, server) {
				if wire, err := k.marshalCreds(&cred); err == nil {
					stale = append(stale, wire)
					c.log.Debug("evicting service ticket", "server", server.UnparseName(),
						"expires", end, "remaining", left)
				}
			}
		}
		C.krb5_free_cred_contents(k.ctx, &cred)
	}
	C.krb5_cc_end_seq_get(k.ctx, k.cc, &cursor)

	// Remove after the cursor is closed rather than mutating the cache
	// mid-iteration.
	for _, wire := range stale {
		if err := k.removeCredExact(wire); err != nil {
			c.log.Warn("could not evict stale service ticket", "error", err)
		}
	}
}

// Run performs credential maintenance in the background until ctx is
// cancelled: renewing the TGT at its half-life, retrying with backoff
// on failure. Requests also trigger maintenance, but a TGT that nobody
// asks about would otherwise miss its renewal window.
func (c *Client) Run(ctx context.Context) {
	for {
		now := time.Now()
		if k, err := c.acquire(); err != nil {
			c.log.Error("background maintenance skipped", "error", err)
		} else {
			c.maintain(k, now)
			c.release(k)
		}
		c.mu.RLock()
		next := c.nextWake(now)
		c.mu.RUnlock()

		timer := time.NewTimer(time.Until(next))
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
	}
}
