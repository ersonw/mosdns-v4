package fakeipnat

// This file keeps the live traffic records of the addresses an administrator
// asked to watch. It is deliberately independent of the data path: the tun
// reader and the conntrack poller both feed the same small ring, so the
// Telegram bot can render one identical message whichever plane is active.

import (
	"encoding/binary"
	"fmt"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	fakeipadmin "github.com/ersonw/mosdns-v4/pkg/fakeip_admin"
)

const (
	// watchEventsKeep bounds one source's ring. The bot shows 20, leaving room
	// for flows that were evicted between two polls.
	watchEventsKeep = 64
	// watchSnapshotDefault is used when a caller asks for an unusable limit.
	watchSnapshotDefault = 20
)

// trafficWatch is the shared registry. A source only pays the parsing cost
// while at least one administrator watches it.
type trafficWatch struct {
	mu      sync.RWMutex
	enabled int32
	sources map[string]*watchSource
}

type watchSource struct {
	refs    int
	version uint64
	events  []fakeipadmin.TrafficEvent // oldest first
}

func newTrafficWatch() *trafficWatch {
	return &trafficWatch{sources: make(map[string]*watchSource)}
}

// add registers one reference. The first reference returns true, which is
// where the non-tun path starts its conntrack poller.
func (w *trafficWatch) add(sourceIP string) bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	s, ok := w.sources[sourceIP]
	if ok {
		s.refs++
		return false
	}
	w.sources[sourceIP] = &watchSource{refs: 1}
	atomic.StoreInt32(&w.enabled, 1)
	return true
}

// remove drops one reference. The last reference returns true.
func (w *trafficWatch) remove(sourceIP string) bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	s, ok := w.sources[sourceIP]
	if !ok {
		return false
	}
	s.refs--
	if s.refs > 0 {
		return false
	}
	delete(w.sources, sourceIP)
	if len(w.sources) == 0 {
		atomic.StoreInt32(&w.enabled, 0)
	}
	return true
}

func (w *trafficWatch) active() bool {
	return atomic.LoadInt32(&w.enabled) == 1
}

func (w *trafficWatch) watched(sourceIP string) bool {
	if !w.active() {
		return false
	}
	w.mu.RLock()
	defer w.mu.RUnlock()
	_, ok := w.sources[sourceIP]
	return ok
}

// record merges one observation into the source's ring. A repeated flow moves
// to the end and keeps its first-seen identity, so a high-rate connection does
// not fill the twenty visible slots with copies of one packet.
func (w *trafficWatch) record(event fakeipadmin.TrafficEvent) {
	w.mu.Lock()
	defer w.mu.Unlock()
	s, ok := w.sources[event.ClientIP]
	if !ok {
		return
	}
	if event.Time == 0 {
		event.Time = time.Now().Unix()
	}
	key := trafficEventKey(event)
	for i, old := range s.events {
		if trafficEventKey(old) != key {
			continue
		}
		if event.Time > old.Time {
			old.Time = event.Time
		}
		if event.Packets > 0 {
			old.Packets += event.Packets
		}
		if event.Domain != "" {
			old.Domain = event.Domain
		}
		if event.DestinationIP != "" {
			old.DestinationIP = event.DestinationIP
		}
		if event.FakeIP != "" {
			old.FakeIP = event.FakeIP
		}
		s.events = append(append(s.events[:i], s.events[i+1:]...), old)
		s.version++
		return
	}
	s.events = append(s.events, event)
	if len(s.events) > watchEventsKeep {
		s.events = s.events[len(s.events)-watchEventsKeep:]
	}
	s.version++
}

// snapshot returns the newest flows first and the source's current version.
func (w *trafficWatch) snapshot(sourceIP string, limit int) ([]fakeipadmin.TrafficEvent, uint64, bool) {
	w.mu.RLock()
	defer w.mu.RUnlock()
	s, ok := w.sources[sourceIP]
	if !ok {
		return nil, 0, false
	}
	if limit <= 0 || limit > watchEventsKeep {
		limit = watchSnapshotDefault
	}
	n := len(s.events)
	if n > limit {
		n = limit
	}
	out := make([]fakeipadmin.TrafficEvent, n)
	for i := 0; i < n; i++ {
		out[i] = s.events[len(s.events)-1-i]
	}
	return out, s.version, true
}

// trafficEventKey identifies a flow. The fake address is preferred over the
// displayed destination: the destination becomes the real address once the
// mapping is known, and that must update the same record, not create a second.
func trafficEventKey(event fakeipadmin.TrafficEvent) string {
	destination := event.FakeIP
	if destination == "" {
		destination = event.DestinationIP
	}
	return fmt.Sprintf("%s|%s|%d|%s|%d", event.ClientIP, event.Protocol,
		event.ClientPort, destination, event.DestinationPort)
}

// packetFlow is the small subset of an IPv4 packet the watch needs. It does
// not use packetView because ICMP has no ports and is still worth showing.
type packetFlow struct {
	src     netip.Addr
	dst     netip.Addr
	proto   string
	srcPort uint16
	dstPort uint16
}

func parseWatchPacket(pkt []byte) (packetFlow, bool) {
	if len(pkt) < ipv4HeaderMinLen || pkt[0]>>4 != 4 {
		return packetFlow{}, false
	}
	ihl := int(pkt[0]&0x0f) * 4
	if ihl < ipv4HeaderMinLen || len(pkt) < ihl {
		return packetFlow{}, false
	}
	total := int(binary.BigEndian.Uint16(pkt[2:4]))
	if total < ihl || total > len(pkt) {
		return packetFlow{}, false
	}
	if binary.BigEndian.Uint16(pkt[6:8])&ipv4FragMask != 0 {
		return packetFlow{}, false
	}

	flow := packetFlow{
		src: netip.AddrFrom4([4]byte{pkt[12], pkt[13], pkt[14], pkt[15]}),
		dst: netip.AddrFrom4([4]byte{pkt[16], pkt[17], pkt[18], pkt[19]}),
	}
	switch pkt[9] {
	case protoTCP:
		flow.proto = "tcp"
	case protoUDP:
		flow.proto = "udp"
	case protoICMP:
		flow.proto = "icmp"
	default:
		return packetFlow{}, false
	}
	if flow.proto != "icmp" {
		if total < ihl+4 {
			return packetFlow{}, false
		}
		flow.srcPort = binary.BigEndian.Uint16(pkt[ihl : ihl+2])
		flow.dstPort = binary.BigEndian.Uint16(pkt[ihl+2 : ihl+4])
	}
	return flow, true
}
