package krb5c

import (
	"os"
	"syscall"
	"time"

	"github.com/jake-scott/kcmex/internal/kcmproto"
)

// tktFlgRenewable is TKT_FLG_RENEWABLE from krb5.h, duplicated here so
// the pure-Go policy code (and its tests) need no cgo.
const tktFlgRenewable int32 = 0x00800000

// Maintenance timing. The background loop never sleeps longer than
// maxSleep (so a wall-clock jump is noticed within bounded time). The
// source ccache is re-read on demand, at most once per
// fileCheckInterval, so a burst of requests against an expired TGT
// does not parse it over and over.
const (
	maxSleep          = 10 * time.Minute
	minBackoff        = 30 * time.Second
	maxBackoff        = 10 * time.Minute
	fileCheckInterval = 5 * time.Second
)

// tgtInfo is what the daemon remembers about its local ticket-granting
// ticket. wire is the credential exactly as libkrb5 marshals it,
// including the session key and the real ticket flags; the copy in the
// working cache has TKT_FLG_RENEWABLE cleared (see storeTGT).
type tgtInfo struct {
	wire           []byte
	client, server kcmproto.Principal
	flags          int32
	authTime       time.Time
	startTime      time.Time
	endTime        time.Time
	renewTill      time.Time
}

// renewable reports whether a renewal could extend the TGT at all: the
// KDC marked it renewable, and its renewable lifetime outlasts its
// current end time.
func (t *tgtInfo) renewable() bool {
	return t.flags&tktFlgRenewable != 0 && t.renewTill.After(t.endTime)
}

func (t *tgtInfo) expired(now time.Time) bool { return !now.Before(t.endTime) }

func (t *tgtInfo) remaining(now time.Time) time.Duration { return t.endTime.Sub(now) }

// canRenew reports whether a renewal is worth attempting right now: the
// KDC only renews a ticket that is still valid.
func (t *tgtInfo) canRenew(now time.Time) bool { return t.renewable() && !t.expired(now) }

// renewPoint is the moment at which the daemon starts trying to renew:
// the TGT's half-life. Renewing early costs nothing (the renewed ticket
// gets a full new lifetime, capped at renew_till) and leaves a long
// window to retry if the KDC is unreachable.
func (t *tgtInfo) renewPoint() time.Time {
	start := t.startTime
	if start.IsZero() {
		start = t.authTime
	}
	return start.Add(t.endTime.Sub(start) / 2)
}

func (t *tgtInfo) renewDue(now time.Time) bool {
	return t.canRenew(now) && !now.Before(t.renewPoint())
}

// nextWake decides when the background maintenance loop should run
// next, given the state maintain() just left behind. Only renewal is
// time-driven; everything else (re-reading the source ccache, sweeping)
// happens on demand as requests arrive. The caller holds c.mu.
func (c *Client) nextWake(now time.Time) time.Time {
	at := now.Add(maxSleep)
	if c.tgt != nil && c.tgt.canRenew(now) {
		at = c.tgt.renewPoint()
		if !at.After(now) {
			// Renewal is due but the last attempt failed; wait out the
			// backoff.
			at = c.renewRetryAt
		}
	}
	if at.After(now.Add(maxSleep)) {
		at = now.Add(maxSleep)
	}
	if !at.After(now) {
		at = now.Add(time.Second)
	}
	return at
}

// noteRenewFailure schedules the next renewal attempt with exponential
// backoff, so a KDC outage is retried without hammering it.
func (c *Client) noteRenewFailure(now time.Time) {
	if c.renewBackoff == 0 {
		c.renewBackoff = minBackoff
	} else {
		c.renewBackoff *= 2
		if c.renewBackoff > maxBackoff {
			c.renewBackoff = maxBackoff
		}
	}
	c.renewRetryAt = now.Add(c.renewBackoff)
}

func (c *Client) resetRenewBackoff() {
	c.renewBackoff = 0
	c.renewRetryAt = time.Time{}
}

// fileOwner returns the uid owning path.
func fileOwner(path string) (int, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return -1, err
	}
	if st, ok := fi.Sys().(*syscall.Stat_t); ok {
		return int(st.Uid), nil
	}
	return -1, nil // cannot tell on this platform
}

// isLocalTGT reports whether a credential is the client's own
// ticket-granting ticket: krbtgt/REALM@REALM for the client's realm.
// Cross-realm TGTs (krbtgt/OTHER@REALM) are intermediate credentials
// libkrb5 obtains on the way to a foreign service and are treated like
// service tickets here.
func isLocalTGT(client, server kcmproto.Principal) bool {
	return isTGTServer(server) &&
		server.Components[1] == server.Realm &&
		server.Realm == client.Realm
}
