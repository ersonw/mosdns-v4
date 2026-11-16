package cbp

import (
	"sync"
	"time"
)

const (
	// DefaultSendWindowPackets caps in-flight packets per session.
	DefaultSendWindowPackets = 32
	// DefaultSendInitialPackets is the initial congestion window.
	DefaultSendInitialPackets = 8
	// DefaultSendRTO is the starting retransmission timeout.
	DefaultSendRTO = 300 * time.Millisecond
	// DefaultSendMinRTO is the floor for the measured RTO.
	DefaultSendMinRTO = 50 * time.Millisecond
	// DefaultSendMaxRTO is the ceiling for the measured RTO.
	DefaultSendMaxRTO = 2 * time.Second
	// DefaultSendRetries is how often one fragment may be transmitted.
	DefaultSendRetries = 3
	// DefaultSendQueuePackets bounds the unaccepted packet queue.
	DefaultSendQueuePackets = 256
	// DefaultSendPacketAge bounds how long a packet stays for repair.
	DefaultSendPacketAge = 30 * time.Second
)

// SendWindowConfig wires the window to the session's datagram writer.
type SendWindowConfig struct {
	Write           func(DataPacket) error
	ACKSnapshot     func() (base uint64, bitmap uint64)
	MaxPackets      int
	InitialPackets  int
	RTO             time.Duration
	MinRTO          time.Duration
	MaxRTO          time.Duration
	MaxRetries      int
	MaxQueuePackets int
	MaxPacketAge    time.Duration
	OnRepair        func(blocks int)
	OnLost          func(blocks int)
	OnQueueDrop     func(packets int)
}

// SendWindow turns whole IP packets into acknowledged, retransmitted datagrams.
// It is the reliability layer that a QUIC datagram does not provide.
type SendWindow struct {
	cfg SendWindowConfig

	mu       sync.Mutex
	queue    []*outPacket
	inflight []*outPacket
	closed   bool
	stop     chan struct{}
	signal   chan struct{}
	started  bool

	cwnd     int
	rto      time.Duration
	srtt     time.Duration
	rttvar   time.Duration
	rttValid bool

	queueDrops uint64
	lastLoss   time.Time
}

type outPacket struct {
	sessionID    uint64
	packetID     uint64
	frags        []outFrag
	acked        map[uint64]bool
	attempts     int
	lastSend     time.Time
	started      time.Time
	lostReported bool
}

type outFrag struct {
	blockID uint64
	flags   uint8
	index   uint16
	count   uint16
	payload []byte
}

// NewSendWindow builds a window with the defaults filled in.
func NewSendWindow(cfg SendWindowConfig) *SendWindow {
	if cfg.MaxPackets <= 0 {
		cfg.MaxPackets = DefaultSendWindowPackets
	}
	if cfg.InitialPackets <= 0 {
		cfg.InitialPackets = DefaultSendInitialPackets
	}
	if cfg.InitialPackets > cfg.MaxPackets {
		cfg.InitialPackets = cfg.MaxPackets
	}
	if cfg.RTO <= 0 {
		cfg.RTO = DefaultSendRTO
	}
	if cfg.MinRTO <= 0 {
		cfg.MinRTO = DefaultSendMinRTO
	}
	if cfg.MaxRTO < cfg.MinRTO {
		cfg.MaxRTO = DefaultSendMaxRTO
	}
	if cfg.MaxRetries <= 0 {
		cfg.MaxRetries = DefaultSendRetries
	}
	if cfg.MaxQueuePackets <= 0 {
		cfg.MaxQueuePackets = DefaultSendQueuePackets
	}
	if cfg.MaxPacketAge <= 0 {
		cfg.MaxPacketAge = DefaultSendPacketAge
	}
	return &SendWindow{
		cfg:    cfg,
		stop:   make(chan struct{}),
		signal: make(chan struct{}, 1),
		cwnd:   cfg.InitialPackets,
		rto:    cfg.RTO,
	}
}

// Start launches the dispatch loop.
func (w *SendWindow) Start() {
	w.mu.Lock()
	if w.started {
		w.mu.Unlock()
		return
	}
	w.started = true
	w.mu.Unlock()
	go w.run()
}

// Push queues one whole IP packet and returns immediately. A full queue drops
// the packet instead of growing memory without bound.
func (w *SendWindow) Push(sessionID, packetID uint64, blockIDs []uint64, flags []uint8, payloads [][]byte) bool {
	if len(blockIDs) == 0 || len(blockIDs) != len(flags) || len(blockIDs) != len(payloads) {
		return false
	}
	p := &outPacket{
		sessionID: sessionID,
		packetID:  packetID,
		frags:     make([]outFrag, len(blockIDs)),
		acked:     make(map[uint64]bool, len(blockIDs)),
	}
	for i := range blockIDs {
		p.frags[i] = outFrag{
			blockID: blockIDs[i],
			flags:   flags[i],
			index:   uint16(i),
			count:   uint16(len(blockIDs)),
			payload: payloads[i],
		}
	}
	w.mu.Lock()
	if w.closed {
		w.mu.Unlock()
		return false
	}
	if w.cfg.MaxQueuePackets > 0 && len(w.queue) >= w.cfg.MaxQueuePackets {
		w.queueDrops++
		w.mu.Unlock()
		if w.cfg.OnQueueDrop != nil {
			w.cfg.OnQueueDrop(1)
		}
		return false
	}
	w.queue = append(w.queue, p)
	w.mu.Unlock()
	w.wake()
	return true
}

// Ack applies a cumulative base plus bitmap from the peer.
func (w *SendWindow) Ack(base, bitmap uint64) {
	w.mu.Lock()
	for _, p := range w.inflight {
		wasAcked := allAcked(p)
		for _, f := range p.frags {
			if f.blockID < base {
				p.acked[f.blockID] = true
				continue
			}
			if f.blockID-base < 64 && bitmap&(uint64(1)<<(f.blockID-base)) != 0 {
				p.acked[f.blockID] = true
			}
		}
		if !wasAcked && allAcked(p) {
			if p.attempts == 1 && !p.lastSend.IsZero() {
				w.updateRTT(time.Since(p.lastSend))
			}
			if w.cwnd < w.cfg.MaxPackets {
				w.cwnd++
			}
		}
	}
	w.pruneLocked()
	w.mu.Unlock()
	w.wake()
}

// Repair re-sends only the fragments the peer reported missing.
func (w *SendWindow) Repair(base, bitmap uint64) {
	w.mu.Lock()
	changed := false
	for _, p := range w.inflight {
		for _, f := range p.frags {
			if f.blockID < base {
				continue
			}
			offset := f.blockID - base
			if offset >= 64 {
				continue
			}
			if bitmap&(uint64(1)<<offset) != 0 {
				p.acked[f.blockID] = true
				continue
			}
			if p.acked[f.blockID] {
				continue
			}
			p.attempts = 0
			p.lastSend = time.Time{}
			p.lostReported = false
			changed = true
		}
	}
	w.mu.Unlock()
	if changed {
		w.wake()
	}
}

// QueueDrops reports packets rejected because the queue was full.
func (w *SendWindow) QueueDrops() uint64 {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.queueDrops
}

// Close stops the dispatch loop.
func (w *SendWindow) Close() {
	w.mu.Lock()
	if w.closed {
		w.mu.Unlock()
		return
	}
	w.closed = true
	w.mu.Unlock()
	close(w.stop)
}

func (w *SendWindow) run() {
	timer := time.NewTimer(w.rto)
	defer timer.Stop()
	for {
		select {
		case <-w.stop:
			return
		case <-w.signal:
		case <-timer.C:
		}
		w.dispatch()
		next := w.nextDeadline()
		if !timer.Stop() {
			select {
			case <-timer.C:
			default:
			}
		}
		timer.Reset(next)
	}
}

func (w *SendWindow) dispatch() {
	w.mu.Lock()
	if w.closed {
		w.mu.Unlock()
		return
	}
	now := time.Now()
	for len(w.inflight) < w.cwnd && w.cwnd <= w.cfg.MaxPackets && len(w.queue) > 0 {
		p := w.queue[0]
		w.queue = w.queue[1:]
		p.started = now
		w.inflight = append(w.inflight, p)
	}
	var send []*outPacket
	var lost int
	keep := w.inflight[:0]
	for _, p := range w.inflight {
		if allAcked(p) {
			continue
		}
		expired := !p.started.IsZero() && w.cfg.MaxPacketAge > 0 && now.Sub(p.started) > w.cfg.MaxPacketAge
		if p.lastSend.IsZero() || now.Sub(p.lastSend) >= w.rto {
			if p.attempts >= w.cfg.MaxRetries {
				if !p.lostReported {
					lost += len(p.frags) - len(p.acked)
					p.lostReported = true
				}
				if expired {
					continue
				}
			} else {
				if expired {
					continue
				}
				send = append(send, p)
			}
		}
		keep = append(keep, p)
	}
	w.inflight = keep
	if lost > 0 {
		w.backoff(now)
	}
	w.mu.Unlock()
	if lost > 0 && w.cfg.OnLost != nil {
		w.cfg.OnLost(lost)
	}
	for _, p := range send {
		w.transmit(p, true)
	}
}

func (w *SendWindow) transmit(p *outPacket, retry bool) {
	w.mu.Lock()
	if w.closed {
		w.mu.Unlock()
		return
	}
	var base, bitmap uint64
	if w.cfg.ACKSnapshot != nil {
		base, bitmap = w.cfg.ACKSnapshot()
	}
	var missing []outFrag
	for _, f := range p.frags {
		if !p.acked[f.blockID] {
			missing = append(missing, f)
		}
	}
	if len(missing) == 0 {
		w.mu.Unlock()
		return
	}
	now := time.Now()
	p.attempts++
	p.lastSend = now
	w.mu.Unlock()
	if retry && len(missing) < len(p.frags) && w.cfg.OnRepair != nil {
		w.cfg.OnRepair(len(missing))
	}
	for _, f := range missing {
		pkt := DataPacket{
			Type:         DataTypeData,
			Flags:        f.flags,
			SessionID:    p.sessionID,
			PacketID:     p.packetID,
			BlockID:      f.blockID,
			FragIndex:    f.index,
			FragCount:    f.count,
			AckBase:      base,
			AckBitmap:    bitmap,
			SendTSMillis: UnixMillis(now),
			Payload:      f.payload,
		}
		if w.cfg.Write != nil {
			_ = w.cfg.Write(pkt)
		}
	}
}

func (w *SendWindow) updateRTT(sample time.Duration) {
	if sample <= 0 {
		return
	}
	if !w.rttValid {
		w.srtt = sample
		w.rttvar = sample / 2
		w.rttValid = true
	} else {
		diff := w.srtt - sample
		if diff < 0 {
			diff = -diff
		}
		w.rttvar = (3*w.rttvar + diff) / 4
		w.srtt = (7*w.srtt + sample) / 8
	}
	rto := w.srtt + 4*w.rttvar
	if rto < w.cfg.MinRTO {
		rto = w.cfg.MinRTO
	}
	if rto > w.cfg.MaxRTO {
		rto = w.cfg.MaxRTO
	}
	w.rto = rto
}

func (w *SendWindow) backoff(now time.Time) {
	if !w.lastLoss.IsZero() && now.Sub(w.lastLoss) < w.rto {
		return
	}
	w.lastLoss = now
	if w.cwnd > 1 {
		w.cwnd /= 2
	}
	if w.cwnd < 2 {
		w.cwnd = 2
	}
	rto := w.rto * 2
	if rto > w.cfg.MaxRTO {
		rto = w.cfg.MaxRTO
	}
	w.rto = rto
}

func (w *SendWindow) pruneLocked() {
	keep := w.inflight[:0]
	for _, p := range w.inflight {
		if !allAcked(p) {
			keep = append(keep, p)
		}
	}
	w.inflight = keep
}

func (w *SendWindow) nextDeadline() time.Duration {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed {
		return time.Hour
	}
	if len(w.queue) > 0 && len(w.inflight) < w.cwnd {
		return 0
	}
	if len(w.inflight) == 0 {
		return time.Hour
	}
	var next time.Duration
	for _, p := range w.inflight {
		if p.attempts >= w.cfg.MaxRetries && p.lostReported {
			continue
		}
		if p.lastSend.IsZero() {
			return 0
		}
		remain := w.rto - time.Since(p.lastSend)
		if next == 0 || remain < next {
			next = remain
		}
	}
	if next <= 0 {
		return time.Millisecond
	}
	return next
}

func (w *SendWindow) wake() {
	select {
	case w.signal <- struct{}{}:
	default:
	}
}

func allAcked(p *outPacket) bool {
	for _, f := range p.frags {
		if !p.acked[f.blockID] {
			return false
		}
	}
	return true
}
