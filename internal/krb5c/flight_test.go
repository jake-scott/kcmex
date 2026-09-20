package krb5c

import (
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestFlightGroupCoalesces(t *testing.T) {
	var g flightGroup
	var calls atomic.Int32
	release := make(chan struct{})
	started := make(chan struct{})

	fn := func() ([]byte, error) {
		calls.Add(1)
		close(started)
		<-release
		return []byte("ticket"), nil
	}

	const n = 8
	var wg sync.WaitGroup
	results := make([][]byte, n)
	errs := make([]error, n)

	// The leader starts and blocks inside fn; the followers must then
	// join it rather than call fn themselves.
	wg.Add(1)
	go func() {
		defer wg.Done()
		results[0], errs[0] = g.do("k", fn)
	}()
	<-started
	for i := 1; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			results[i], errs[i] = g.do("k", fn)
		}(i)
	}
	// A different key is independent and runs immediately.
	other, err := g.do("other", func() ([]byte, error) { return []byte("x"), errors.New("boom") })
	if string(other) != "x" || err == nil {
		t.Errorf("other key: got %q, %v", other, err)
	}

	// Only let the leader finish once every follower has joined it;
	// otherwise a late follower would legitimately start its own flight.
	deadline := time.Now().Add(5 * time.Second)
	for g.joined.Load() < n-1 {
		if time.Now().After(deadline) {
			t.Fatalf("only %d of %d followers joined the flight", g.joined.Load(), n-1)
		}
		time.Sleep(time.Millisecond)
	}
	close(release)
	wg.Wait()

	if got := calls.Load(); got != 1 {
		t.Errorf("fn ran %d times, want 1", got)
	}
	for i := range results {
		if string(results[i]) != "ticket" || errs[i] != nil {
			t.Errorf("caller %d: got %q, %v", i, results[i], errs[i])
		}
	}
	// Callers get independent copies.
	results[0][0] = 'X'
	if string(results[1]) != "ticket" {
		t.Errorf("results alias each other: %q", results[1])
	}

	// Once the flight is over, the key is free for a fresh call.
	calls.Store(0)
	if _, err := g.do("k", func() ([]byte, error) { calls.Add(1); return nil, nil }); err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 1 {
		t.Errorf("stale flight entry: fn ran %d times", calls.Load())
	}
}
