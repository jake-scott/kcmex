package krb5c

import (
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jake-scott/kcmex/internal/kcmproto"
)

// TestLive exercises the credential-lifetime machinery against a real
// KDC. It is skipped unless KCMEX_LIVE_CCACHE names a FILE ccache with
// a valid (preferably renewable) TGT; the file is copied and never
// modified. KCMEX_LIVE_SERVICE (default HTTP/foo.poptart.org) must be a
// service principal the KDC knows. KRB5_CONFIG must reach the KDC.
func TestLive(t *testing.T) {
	src := os.Getenv("KCMEX_LIVE_CCACHE")
	if src == "" {
		t.Skip("KCMEX_LIVE_CCACHE not set")
	}
	svc := os.Getenv("KCMEX_LIVE_SERVICE")
	if svc == "" {
		svc = "HTTP/foo.poptart.org"
	}

	data, err := os.ReadFile(src)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "cc")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}

	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug}))
	c, err := Open(path, Options{MinTicketLife: 5 * time.Minute, OwnerUID: os.Getuid(), Log: log})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if c.tgt == nil {
		t.Fatal("no TGT in ccache")
	}
	fileTGTEnd := c.tgt.endTime
	now := time.Now()

	mc := kcmproto.MatchCredential{
		HasServer: true,
		Server:    kcmproto.Principal{Type: 1, Realm: c.tgt.client.Realm, Components: strings.Split(svc, "/")},
		EndTime:   int32(now.Unix()), // as the MIT client sends it
	}

	// 1. A freshly fetched service ticket inherits the TGT's end time and
	//    is not renewable.
	wire, err := c.Retrieve(mc)
	if err != nil {
		t.Fatalf("Retrieve: %v", err)
	}
	sum, err := c.SummarizeCredential(wire)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := sum.EndTime, int32(c.tgt.endTime.Unix()); got != want {
		t.Errorf("service ticket ends %s, want TGT end %s", kcmproto.FormatTimestamp(got), kcmproto.FormatTimestamp(want))
	}
	if sum.TicketFlags&uint32(tktFlgRenewable) != 0 || sum.RenewTill != 0 {
		t.Errorf("service ticket is renewable: flags=0x%08x renew_till=%s", sum.TicketFlags, kcmproto.FormatTimestamp(sum.RenewTill))
	}
	if left := time.Unix(int64(uint32(sum.EndTime)), 0).Sub(now); left < 30*time.Minute {
		t.Errorf("service ticket only has %v left", left)
	}

	// 2. Listings show the TGT with its real flags.
	tgtEntries, svcEntries := splitEntries(t, c, svc)
	if len(tgtEntries) != 1 {
		t.Fatalf("listing has %d TGT entries, want 1", len(tgtEntries))
	}
	if c.tgt.renewable() && tgtEntries[0].TicketFlags&uint32(tktFlgRenewable) == 0 {
		t.Errorf("listed TGT lost its renewable flag: 0x%08x", tgtEntries[0].TicketFlags)
	}
	if len(svcEntries) != 1 {
		t.Errorf("listing has %d %s entries, want 1", len(svcEntries), svc)
	}

	// 3. Renewal replaces the TGT with a longer-lived one.
	if c.tgt.renewable() {
		c.mu.Lock()
		err := c.renewTGT(now)
		c.mu.Unlock()
		if err != nil {
			t.Fatalf("renewTGT: %v", err)
		}
		if !c.tgt.endTime.After(fileTGTEnd) {
			t.Errorf("renewed TGT ends %v, not after %v", c.tgt.endTime, fileTGTEnd)
		}
		tgtEntries, _ = splitEntries(t, c, svc)
		if len(tgtEntries) != 1 || tgtEntries[0].EndTime != int32(c.tgt.endTime.Unix()) {
			t.Errorf("after renewal listing has %d TGT entries (%+v), want exactly the renewed one", len(tgtEntries), tgtEntries)
		}
	} else {
		t.Log("TGT not renewable; skipping renewal check")
	}

	// 4. A near-expiry service ticket is evicted by the sweep while the
	//    long-lived one for the same service stays.
	short, err := c.withEndTime(wire, now.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Store(short); err != nil {
		t.Fatal(err)
	}
	c.mu.Lock()
	c.sweep(now)
	c.mu.Unlock()
	_, svcEntries = splitEntries(t, c, svc)
	if len(svcEntries) != 1 || time.Unix(int64(uint32(svcEntries[0].EndTime)), 0).Sub(now) < 30*time.Minute {
		t.Errorf("after sweep: %d %s entries (%+v), want only the long-lived one", len(svcEntries), svc, svcEntries)
	}

	// 5. With an expired TGT and no readable source file, RETRIEVE fails
	//    with "ticket expired".
	c.mu.Lock()
	c.tgt.endTime = now.Add(-time.Second)
	c.tgt.flags &^= tktFlgRenewable
	c.lastFileCheck = time.Time{}
	c.mu.Unlock()
	gone := path + ".gone"
	if err := os.Rename(path, gone); err != nil {
		t.Fatal(err)
	}
	_, err = c.Retrieve(mc)
	var kerr *Error
	if !errors.As(err, &kerr) || kerr.Code != TktExpired {
		t.Errorf("Retrieve with expired TGT: got %v, want code %d", err, TktExpired)
	}

	// 6. Once the source file is back with a TGT that outlives the held
	//    one, the next request adopts it and works again.
	if err := os.Rename(gone, path); err != nil {
		t.Fatal(err)
	}
	c.mu.Lock()
	c.lastFileCheck = time.Time{} // defeat the re-read throttle
	c.mu.Unlock()
	wire, err = c.Retrieve(mc)
	if err != nil {
		t.Fatalf("Retrieve after reload: %v", err)
	}
	if !c.tgt.endTime.Equal(fileTGTEnd) {
		t.Errorf("after reload TGT ends %v, want file's %v", c.tgt.endTime, fileTGTEnd)
	}
	if c.tgt.flags&tktFlgRenewable == 0 {
		t.Errorf("reloaded TGT lost its flags: 0x%08x", c.tgt.flags)
	}
	sum, _ = c.SummarizeCredential(wire)
	if sum.EndTime != int32(fileTGTEnd.Unix()) {
		t.Errorf("service ticket after reload ends %s, want %s", kcmproto.FormatTimestamp(sum.EndTime), fileTGTEnd)
	}

	// 7. A file whose TGT is older than the (renewed) one held is left
	//    alone, even when the held TGT is due for attention.
	if c.tgt.renewable() {
		c.mu.Lock()
		err := c.renewTGT(now)
		renewedEnd := c.tgt.endTime
		c.tgt.startTime = now.Add(-20 * time.Hour) // make renewal "due" again
		c.lastFileCheck = time.Time{}
		c.maintain(now)
		kept := c.tgt.endTime
		c.mu.Unlock()
		if err != nil {
			t.Fatalf("second renewTGT: %v", err)
		}
		if kept.Before(renewedEnd) {
			t.Errorf("maintain replaced a renewed TGT (ends %v) with the older file TGT (ends %v)", renewedEnd, kept)
		}
	}
}

// splitEntries lists the working cache and summarises the TGT entries
// and the entries for svc.
func splitEntries(t *testing.T, c *Client, svc string) (tgts, svcs []CredentialSummary) {
	t.Helper()
	entries, err := c.ListEntries()
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		sum, err := c.SummarizeCredential(e.Wire)
		if err != nil {
			t.Fatal(err)
		}
		switch {
		case isTGTServer(e.Server):
			tgts = append(tgts, sum)
		case strings.Join(e.Server.Components, "/") == svc:
			svcs = append(svcs, sum)
		}
	}
	return tgts, svcs
}
