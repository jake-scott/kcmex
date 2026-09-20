package krb5c

import (
	"testing"
	"time"

	"github.com/jake-scott/kcmex/internal/kcmproto"
)

var (
	t0    = time.Date(2026, 9, 20, 15, 0, 0, 0, time.UTC)
	hour  = time.Hour
	realm = "EXAMPLE.COM"
	alice = kcmproto.Principal{Realm: realm, Components: []string{"alice"}}
	tgtSP = kcmproto.Principal{Realm: realm, Components: []string{"krbtgt", realm}}
)

func newTGT(life, renewFor time.Duration, renewable bool) *tgtInfo {
	t := &tgtInfo{
		client:    alice,
		server:    tgtSP,
		authTime:  t0,
		startTime: t0,
		endTime:   t0.Add(life),
	}
	if renewable {
		t.flags = tktFlgRenewable
		t.renewTill = t0.Add(renewFor)
	}
	return t
}

func TestRenewDecisions(t *testing.T) {
	tgt := newTGT(10*hour, 24*hour, true)

	if tgt.renewDue(t0.Add(4 * hour)) {
		t.Error("renewal due before half-life")
	}
	if !tgt.renewDue(t0.Add(5 * hour)) {
		t.Error("renewal not due at half-life")
	}
	if !tgt.renewDue(t0.Add(9*hour + 59*time.Minute)) {
		t.Error("renewal not due just before expiry")
	}
	if tgt.renewDue(t0.Add(10 * hour)) {
		t.Error("renewal due after expiry; the KDC would refuse it")
	}

	// Not renewable at all.
	plain := newTGT(10*hour, 0, false)
	if plain.renewDue(t0.Add(9 * hour)) {
		t.Error("non-renewable TGT reported as renewable")
	}

	// Renewable flag set, but renew_till already reached by end time:
	// a renewal cannot extend anything.
	capped := newTGT(10*hour, 10*hour, true)
	if capped.renewable() {
		t.Error("TGT whose renew_till equals its end time reported renewable")
	}
}

func TestNextWake(t *testing.T) {
	c := &Client{minLife: 5 * time.Minute}

	// Renewable and healthy: wake at the half-life, capped at maxSleep.
	c.tgt = newTGT(10*hour, 24*hour, true)
	if got, want := c.nextWake(t0), t0.Add(maxSleep); !got.Equal(want) {
		t.Errorf("healthy renewable: got %v want %v (maxSleep cap)", got, want)
	}
	if got, want := c.nextWake(t0.Add(4*hour+55*time.Minute)), t0.Add(5*hour); !got.Equal(want) {
		t.Errorf("near half-life: got %v want %v", got, want)
	}

	// Renewal due but failed: wake at the retry time.
	now := t0.Add(6 * hour)
	c.noteRenewFailure(now)
	if got, want := c.nextWake(now), now.Add(minBackoff); !got.Equal(want) {
		t.Errorf("after failure: got %v want %v", got, want)
	}
	c.noteRenewFailure(now)
	if c.renewBackoff != 2*minBackoff {
		t.Errorf("backoff did not double: %v", c.renewBackoff)
	}
	for i := 0; i < 10; i++ {
		c.noteRenewFailure(now)
	}
	if c.renewBackoff != maxBackoff {
		t.Errorf("backoff not capped: %v", c.renewBackoff)
	}
	c.resetRenewBackoff()

	// Nothing time-driven to do for an unrenewable, expired or missing
	// TGT: the source ccache is only re-read when a request arrives.
	c.tgt = newTGT(10*hour, 0, false)
	for _, at := range []time.Time{t0, t0.Add(9*hour + 57*time.Minute), t0.Add(11 * hour)} {
		if got, want := c.nextWake(at), at.Add(maxSleep); !got.Equal(want) {
			t.Errorf("unrenewable at %v: got %v want %v", at, got, want)
		}
	}
	c.tgt = nil
	if got, want := c.nextWake(t0), t0.Add(maxSleep); !got.Equal(want) {
		t.Errorf("no tgt: got %v want %v", got, want)
	}
}

func TestIsLocalTGT(t *testing.T) {
	cases := []struct {
		server kcmproto.Principal
		want   bool
	}{
		{tgtSP, true},
		{kcmproto.Principal{Realm: realm, Components: []string{"krbtgt", "OTHER.COM"}}, false},
		{kcmproto.Principal{Realm: "OTHER.COM", Components: []string{"krbtgt", "OTHER.COM"}}, false},
		{kcmproto.Principal{Realm: realm, Components: []string{"host", "www"}}, false},
		{kcmproto.Principal{Realm: realm, Components: []string{"krbtgt"}}, false},
	}
	for _, tc := range cases {
		if got := isLocalTGT(alice, tc.server); got != tc.want {
			t.Errorf("isLocalTGT(%v) = %v, want %v", tc.server, got, tc.want)
		}
	}
}
