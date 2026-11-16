package cbp

import "sync"

const ackWindow = 4096

// AckTracker tracks received block ids and turns them into the cumulative base
// plus 64-bit bitmap the peer needs to stop retransmitting.
type AckTracker struct {
	mu        sync.Mutex
	base      uint64
	seen      map[uint64]struct{}
	received  uint64
	duplicate uint64
}

// NewAckTracker returns an empty tracker whose base is block 0.
func NewAckTracker() *AckTracker {
	return &AckTracker{seen: make(map[uint64]struct{})}
}

// Observe records one received block. It reports whether the block is new;
// duplicates and blocks far beyond the window are ignored.
func (a *AckTracker) Observe(id uint64) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	if id < a.base {
		a.duplicate++
		return false
	}
	if id > a.base+ackWindow {
		return false
	}
	if _, ok := a.seen[id]; ok {
		a.duplicate++
		return false
	}
	a.seen[id] = struct{}{}
	a.received++
	for {
		if _, ok := a.seen[a.base]; !ok {
			break
		}
		delete(a.seen, a.base)
		a.base++
	}
	return true
}

// Snapshot returns the lowest block id not yet received and the bitmap of the
// 64 blocks that follow it.
func (a *AckTracker) Snapshot() (base uint64, bitmap uint64) {
	a.mu.Lock()
	defer a.mu.Unlock()
	base = a.base
	for i := uint64(0); i < 64; i++ {
		if _, ok := a.seen[base+i]; ok {
			bitmap |= 1 << i
		}
	}
	return base, bitmap
}

// Base is the lowest block id not yet received.
func (a *AckTracker) Base() uint64 {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.base
}

// Duplicates counts re-received blocks.
func (a *AckTracker) Duplicates() uint64 {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.duplicate
}
