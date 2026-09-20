package krb5c

import (
	"sync"
	"sync/atomic"
)

// flightGroup coalesces concurrent calls that share a key into a single
// execution whose result every caller receives - the usual
// "singleflight" pattern, kept local to avoid a dependency. Retrieve
// uses it so that a burst of clients asking for the same service
// ticket costs one TGS-REQ and stores one cache entry rather than N.
type flightGroup struct {
	mu sync.Mutex
	m  map[string]*flight

	joined atomic.Int64 // calls answered by another caller's flight
}

type flight struct {
	done chan struct{}
	val  []byte
	err  error
}

// do runs fn for key unless a call for the same key is already in
// progress, in which case it waits for that call and returns its
// result. Every caller gets its own copy of the bytes.
func (g *flightGroup) do(key string, fn func() ([]byte, error)) ([]byte, error) {
	g.mu.Lock()
	if g.m == nil {
		g.m = make(map[string]*flight)
	}
	if f, ok := g.m[key]; ok {
		g.joined.Add(1)
		g.mu.Unlock()
		<-f.done
		return append([]byte(nil), f.val...), f.err
	}
	f := &flight{done: make(chan struct{})}
	g.m[key] = f
	g.mu.Unlock()

	f.val, f.err = fn()

	g.mu.Lock()
	delete(g.m, key)
	g.mu.Unlock()
	close(f.done)
	return f.val, f.err
}
