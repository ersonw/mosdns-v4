package cbp

import (
	"bytes"
	"errors"
	"sync"
	"time"
)

const (
	// DefaultMaxPacketsInFlight bounds partially reassembled packets.
	DefaultMaxPacketsInFlight = 64
	// DefaultReassemblyTimeout drops a stale partial packet.
	DefaultReassemblyTimeout = 300 * time.Millisecond
	// MaxIPPacketBytes is the largest reassembled IP packet.
	MaxIPPacketBytes = 65535
)

var (
	// ErrTooManyFragments rejects a frame claiming more fragments than allowed.
	ErrTooManyFragments = errors.New("cbp: too many fragments")
	// ErrPacketTooLarge rejects a reassembled packet above the IP limit.
	ErrPacketTooLarge = errors.New("cbp: reassembled packet too large")
)

type fragmentState struct {
	fragCount uint16
	frags     [][]byte
	got       uint16
	created   time.Time
	bytes     int
}

// Reassembler rebuilds raw IP packets from fragments. Packets complete out of
// order; each one is returned as soon as its last fragment arrives.
type Reassembler struct {
	mu         sync.Mutex
	packets    map[uint64]*fragmentState
	maxPackets int
	timeout    time.Duration
	drops      uint64
}

// NewReassembler builds a reassembler with bounded memory.
func NewReassembler(maxPackets int, timeout time.Duration) *Reassembler {
	if maxPackets <= 0 {
		maxPackets = DefaultMaxPacketsInFlight
	}
	if timeout <= 0 {
		timeout = DefaultReassemblyTimeout
	}
	return &Reassembler{
		packets:    make(map[uint64]*fragmentState),
		maxPackets: maxPackets,
		timeout:    timeout,
	}
}

// Add consumes one fragment and returns a complete packet when it is the last
// missing piece.
func (r *Reassembler) Add(p DataPacket) ([]byte, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	now := time.Now()
	r.cleanup(now)
	if p.FragCount > 64 {
		r.drops++
		return nil, false
	}
	if p.FragCount == 1 {
		if len(p.Payload) > MaxIPPacketBytes {
			r.drops++
			return nil, false
		}
		return p.Payload, true
	}

	st, ok := r.packets[p.PacketID]
	if !ok {
		if len(r.packets) >= r.maxPackets {
			r.dropOldest()
		}
		st = &fragmentState{
			fragCount: p.FragCount,
			frags:     make([][]byte, int(p.FragCount)),
			created:   now,
		}
		r.packets[p.PacketID] = st
	}
	if st.fragCount != p.FragCount {
		delete(r.packets, p.PacketID)
		r.drops++
		return nil, false
	}
	if st.frags[p.FragIndex] != nil {
		return nil, false
	}
	st.frags[p.FragIndex] = p.Payload
	st.got++
	st.bytes += len(p.Payload)
	if st.bytes > MaxIPPacketBytes {
		delete(r.packets, p.PacketID)
		r.drops++
		return nil, false
	}
	if st.got != st.fragCount {
		return nil, false
	}

	var out bytes.Buffer
	out.Grow(st.bytes)
	for _, frag := range st.frags {
		out.Write(frag)
	}
	delete(r.packets, p.PacketID)
	if out.Len() > MaxIPPacketBytes {
		r.drops++
		return nil, false
	}
	return out.Bytes(), true
}

func (r *Reassembler) cleanup(now time.Time) {
	for id, st := range r.packets {
		if now.Sub(st.created) > r.timeout {
			delete(r.packets, id)
			r.drops++
		}
	}
}

func (r *Reassembler) dropOldest() {
	var oldestID uint64
	var oldest time.Time
	first := true
	for id, st := range r.packets {
		if first || st.created.Before(oldest) {
			first = false
			oldestID = id
			oldest = st.created
		}
	}
	if !first {
		delete(r.packets, oldestID)
		r.drops++
	}
}

// Drops counts packets abandoned by timeout or memory pressure.
func (r *Reassembler) Drops() uint64 {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.drops
}
