package krb5c

import (
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jake-scott/kcmex/internal/kcmproto"
)

const (
	testRealm  = "KCMEX.TEST"
	testClient = "alice@" + testRealm
	testTGT    = "krbtgt/" + testRealm + "@" + testRealm
)

// openSynthetic builds a FILE ccache holding a made-up TGT plus service
// tickets for each of services, and opens a Client on it. Nothing in it
// can authenticate anywhere; it exists to drive the cache paths without
// a KDC. Retrieve on one of services is a cache hit and never leaves
// the process.
func openSynthetic(t *testing.T, services []string, opts Options) (*Client, map[string][]byte) {
	t.Helper()
	now := time.Now().Truncate(time.Second)
	// Not renewable, so no test can ever wander off looking for a KDC.
	tgt, err := synthCredential(testClient, testTGT, now.Add(-time.Hour), now.Add(8*time.Hour), 0)
	if err != nil {
		t.Fatal(err)
	}
	wires := [][]byte{tgt}
	byService := make(map[string][]byte)
	for _, svc := range services {
		w, err := synthCredential(testClient, svc+"@"+testRealm, now.Add(-time.Hour), now.Add(8*time.Hour), 0)
		if err != nil {
			t.Fatal(err)
		}
		wires = append(wires, w)
		byService[svc] = w
	}
	path := filepath.Join(t.TempDir(), "cc")
	if err := writeFileCcache(path, testClient, wires); err != nil {
		t.Fatal(err)
	}
	if opts.OwnerUID == 0 {
		opts.OwnerUID = os.Getuid()
	}
	if opts.Log == nil {
		opts.Log = slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn}))
	}
	c, err := Open(path, opts)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(c.Close)
	return c, byService
}

func matchFor(svc string) kcmproto.MatchCredential {
	return kcmproto.MatchCredential{
		HasServer: true,
		Server:    kcmproto.Principal{Type: 1, Realm: testRealm, Components: strings.Split(svc, "/")},
		EndTime:   int32(time.Now().Unix()),
	}
}

// TestConcurrentOperations hammers a Client from many goroutines with
// every kind of operation at once, with only a few contexts in the
// pool, and checks that answers stay right. Run under -race this is
// the check that pooled contexts really are never shared and that the
// shared MEMORY: cache tolerates concurrent readers, writers and
// re-initialisation.
func TestConcurrentOperations(t *testing.T) {
	services := []string{"host/a.kcmex.test", "host/b.kcmex.test", "HTTP/c.kcmex.test"}
	c, wires := openSynthetic(t, services, Options{MaxConcurrent: 3})

	const workers, rounds = 24, 40
	var wg sync.WaitGroup
	errCh := make(chan error, workers*rounds)

	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			svc := services[w%len(services)]
			for r := 0; r < rounds; r++ {
				switch (w + r) % 5 {
				case 0, 1:
					got, err := c.Retrieve(matchFor(svc))
					if err != nil {
						errCh <- fmt.Errorf("Retrieve(%s): %w", svc, err)
						continue
					}
					if string(got) != string(wires[svc]) {
						errCh <- fmt.Errorf("Retrieve(%s): wrong credential returned", svc)
					}
				case 2:
					entries, err := c.ListEntries()
					if err != nil {
						errCh <- fmt.Errorf("ListEntries: %w", err)
						continue
					}
					tgts := 0
					for _, e := range entries {
						if isTGTServer(e.Server) {
							tgts++
						}
					}
					if tgts != 1 {
						errCh <- fmt.Errorf("ListEntries: %d TGT entries, want 1", tgts)
					}
				case 3:
					if _, err := c.DefaultPrincipal(); err != nil {
						errCh <- fmt.Errorf("DefaultPrincipal: %w", err)
					}
					if _, err := c.SummarizeCredential(wires[svc]); err != nil {
						errCh <- fmt.Errorf("SummarizeCredential: %w", err)
					}
				case 4:
					// Store a short-lived duplicate and let the next
					// sweep (run by any request) evict it again.
					short, err := c.withEndTime(wires[svc], time.Now().Add(time.Minute))
					if err != nil {
						errCh <- err
						continue
					}
					if err := c.Store(short); err != nil {
						errCh <- fmt.Errorf("Store: %w", err)
					}
				}
			}
		}(w)
	}
	wg.Wait()
	close(errCh)
	for err := range errCh {
		t.Error(err)
	}

	// Everything settles: one TGT, one long-lived ticket per service, and
	// no short-lived duplicates left behind by the stores.
	entries, err := c.ListEntries()
	if err != nil {
		t.Fatal(err)
	}
	perServer := map[string]int{}
	for _, e := range entries {
		perServer[e.Server.UnparseName()]++
	}
	if perServer[testTGT] != 1 {
		t.Errorf("TGT entries: %d, want 1", perServer[testTGT])
	}
	for _, svc := range services {
		if n := perServer[svc+"@"+testRealm]; n != 1 {
			t.Errorf("%s entries: %d, want 1 (entries: %v)", svc, n, perServer)
		}
	}
}

// TestConcurrentRetrieveDuringReload checks that a source-ccache reload
// (which re-initialises the working cache) cannot be observed half-way
// by concurrent requests: they either see the old contents or the new.
func TestConcurrentRetrieveDuringReload(t *testing.T) {
	svc := "host/x.kcmex.test"
	c, wires := openSynthetic(t, []string{svc}, Options{MaxConcurrent: 4})

	// Replace the source file with one whose TGT outlives the held one,
	// then make the held TGT look like it needs attention so the next
	// request adopts the file.
	now := time.Now().Truncate(time.Second)
	newTGT, err := synthCredential(testClient, testTGT, now, now.Add(20*time.Hour), tktFlgRenewable)
	if err != nil {
		t.Fatal(err)
	}
	newSvc, err := synthCredential(testClient, svc+"@"+testRealm, now, now.Add(20*time.Hour), 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := writeFileCcache(c.srcPath, testClient, [][]byte{newTGT, newSvc}); err != nil {
		t.Fatal(err)
	}

	const workers = 16
	var wg sync.WaitGroup
	errCh := make(chan error, workers*20)
	start := make(chan struct{})
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			<-start
			for r := 0; r < 20; r++ {
				if w == 0 && r == 5 {
					c.mu.Lock()
					c.tgt.endTime = time.Now().Add(time.Minute) // "close to expiry"
					c.lastFileCheck = time.Time{}
					c.mu.Unlock()
				}
				got, err := c.Retrieve(matchFor(svc))
				if err != nil {
					errCh <- fmt.Errorf("Retrieve: %w", err)
					continue
				}
				if string(got) != string(wires[svc]) && string(got) != string(newSvc) {
					errCh <- errors.New("Retrieve returned neither the old nor the new ticket")
				}
			}
		}(w)
	}
	close(start)
	wg.Wait()
	close(errCh)
	for err := range errCh {
		t.Error(err)
	}

	c.mu.RLock()
	held := c.tgt.endTime
	c.mu.RUnlock()
	if !held.Equal(now.Add(20 * time.Hour)) {
		t.Errorf("held TGT ends %v, want the reloaded file's %v", held, now.Add(20*time.Hour))
	}
	got, err := c.Retrieve(matchFor(svc))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(newSvc) {
		t.Error("after reload, Retrieve still returns the old ticket")
	}
}

// TestRetrieveRefusesTGT is the policy check that survives everything
// else: the TGT is never handed out through RETRIEVE.
func TestRetrieveRefusesTGT(t *testing.T) {
	c, _ := openSynthetic(t, nil, Options{})
	_, err := c.Retrieve(matchFor("krbtgt/" + testRealm))
	var kerr *Error
	if !errors.As(err, &kerr) || kerr.Code != FCCPerm {
		t.Errorf("got %v, want code %d", err, FCCPerm)
	}
}

func TestCloseWaitsForInFlight(t *testing.T) {
	c, _ := openSynthetic(t, []string{"host/y.kcmex.test"}, Options{MaxConcurrent: 2})
	k, err := c.acquire()
	if err != nil {
		t.Fatal(err)
	}
	closed := make(chan struct{})
	go func() {
		c.Close()
		close(closed)
	}()
	select {
	case <-closed:
		t.Fatal("Close returned while a context was still checked out")
	case <-time.After(50 * time.Millisecond):
	}
	c.release(k)
	select {
	case <-closed:
	case <-time.After(5 * time.Second):
		t.Fatal("Close did not return after the last context was released")
	}
}
