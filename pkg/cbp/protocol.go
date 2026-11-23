package cbp

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"sync"
	"time"
)

const (
	Version = 1

	// HeaderSize is the fixed size of a CBP data frame. The payload follows it.
	HeaderSize = 54

	// MaxBlockPayload keeps a CBP datagram inside the IPv6 minimum MTU:
	// 40 (IPv6) + 8 (UDP) + 54 (CBP) + 16 (AEAD) + 1100 = 1218 bytes.
	MaxBlockPayload = 1100

	// MaxControlFrame is a guard against unbounded control-channel frames.
	MaxControlFrame = 1 << 20

	// MaxStreamChunk is the largest payload a peer may put in one STREAM_DATA
	// frame. It stays at 64 KiB for compatibility with older peers.
	MaxStreamChunk = 64 << 10

	// PreferredStreamChunk is what new peers actually send. On a slow
	// cross-border link a 64 KiB frame can occupy the shared writer for
	// ~40 ms, delaying every other stream; 16 KiB bounds that head-of-line
	// wait to ~10 ms at the same throughput while adding little framing cost.
	PreferredStreamChunk = 16 << 10

	// DefaultStreamWindow is the per-stream receive credit advertised during
	// STREAM_OPEN/STREAM_ACK. It bounds both peer memory and bytes in flight.
	DefaultStreamWindow = 2 << 20

	ALPNControl   = "cbp-control/1"
	ALPNControlV2 = "cbp-control/2"
	ALPNData      = "cbp-data/1"

	// StreamFrameMarker distinguishes a binary stream frame from the JSON
	// envelope used by session control messages. JSON objects always start
	// with '{', so one marker byte is enough to demultiplex.
	StreamFrameMarker byte = 0xC1
)

const (
	StreamFrameData byte = iota + 1
	StreamFrameCredit
	StreamFrameFIN
)

type StreamFrame struct {
	Kind     byte
	StreamID uint64
	Credit   uint32
	Data     []byte
}

func DecodeStreamFrame(body []byte) (StreamFrame, error) {
	if len(body) < 10 || body[0] != StreamFrameMarker {
		return StreamFrame{}, ErrBadDataFrame
	}
	kind := body[1]
	id := binary.BigEndian.Uint64(body[2:10])
	switch kind {
	case StreamFrameData:
		if len(body) == 10 {
			return StreamFrame{}, fmt.Errorf("%w: empty stream data", ErrBadDataFrame)
		}
		return StreamFrame{Kind: kind, StreamID: id, Data: body[10:]}, nil
	case StreamFrameCredit:
		if len(body) != 14 {
			return StreamFrame{}, fmt.Errorf("%w: malformed stream credit", ErrBadDataFrame)
		}
		return StreamFrame{Kind: kind, StreamID: id, Credit: binary.BigEndian.Uint32(body[10:14])}, nil
	case StreamFrameFIN:
		if len(body) != 10 {
			return StreamFrame{}, fmt.Errorf("%w: malformed stream fin", ErrBadDataFrame)
		}
		return StreamFrame{Kind: kind, StreamID: id}, nil
	default:
		return StreamFrame{}, fmt.Errorf("%w: stream frame kind %d", ErrBadDataFrame, kind)
	}
}

var streamFramePool = sync.Pool{
	New: func() any {
		buf := make([]byte, 4+10+MaxStreamChunk)
		return &buf
	},
}

// WriteStreamFrame writes exactly one binary stream frame. Header and payload
// are copied into one buffer and written once so TLS does not emit a separate
// record for a tiny header.
func WriteStreamFrame(w io.Writer, frame StreamFrame) error {
	if frame.StreamID == 0 {
		return errors.New("cbp: stream id is required")
	}
	bodyLen := 10
	switch frame.Kind {
	case StreamFrameData:
		if len(frame.Data) == 0 || len(frame.Data) > MaxStreamChunk {
			return ErrPayloadTooLarge
		}
		bodyLen += len(frame.Data)
	case StreamFrameCredit:
	case StreamFrameFIN:
	default:
		return fmt.Errorf("%w: stream frame kind %d", ErrBadDataFrame, frame.Kind)
	}
	if bodyLen > MaxControlFrame {
		return fmt.Errorf("cbp: stream frame exceeds %d bytes", MaxControlFrame)
	}
	raw := streamFramePool.Get().(*[]byte)
	buf := (*raw)[:4+bodyLen]
	buf[0] = 0
	buf[1] = 0
	buf[2] = 0
	buf[3] = 0
	binary.BigEndian.PutUint32(buf[:4], uint32(bodyLen))
	buf[4] = StreamFrameMarker
	buf[5] = frame.Kind
	binary.BigEndian.PutUint64(buf[6:14], frame.StreamID)
	if frame.Kind == StreamFrameData {
		copy(buf[14:], frame.Data)
	}
	if frame.Kind == StreamFrameCredit {
		bodyLen += 4
		buf = (*raw)[:4+bodyLen]
		binary.BigEndian.PutUint32(buf[:4], uint32(bodyLen))
		binary.BigEndian.PutUint32(buf[14:18], frame.Credit)
	}
	_, err := w.Write(buf)
	streamFramePool.Put(raw)
	return err
}

type DataType uint8

const (
	DataTypeData DataType = iota + 1
	DataTypeACK
	DataTypeBind
	DataTypePing
	DataTypeRepair
)

const (
	FlagReliable     uint8 = 1 << 0
	FlagLastFragment uint8 = 1 << 1
	FlagIPv4         uint8 = 1 << 2
	FlagIPv6         uint8 = 1 << 3
	FlagECN          uint8 = 1 << 4
	FlagRepair       uint8 = 1 << 5
	FlagCompressed   uint8 = 1 << 6
)

var (
	ErrShortDataFrame  = errors.New("cbp: short data frame")
	ErrBadDataFrame    = errors.New("cbp: invalid data frame")
	ErrPayloadTooLarge = errors.New("cbp: payload exceeds block limit")
)

// DataPacket is the wire representation of one CBP datagram. DataPayload
// contains one fragment of a raw IPv4/IPv6 packet, or a bind token for
// DataTypeBind. ACK fields are piggybacked on every packet.
type DataPacket struct {
	Version      uint8
	Type         DataType
	Flags        uint8
	SessionID    uint64
	PacketID     uint64
	BlockID      uint64
	FragIndex    uint16
	FragCount    uint16
	AckBase      uint64
	AckBitmap    uint64
	SendTSMillis uint32
	Payload      []byte
}

func (p DataPacket) Encode() ([]byte, error) {
	if len(p.Payload) > MaxBlockPayload {
		return nil, ErrPayloadTooLarge
	}
	if p.FragCount == 0 {
		return nil, fmt.Errorf("%w: frag_count must be positive", ErrBadDataFrame)
	}
	buf := make([]byte, HeaderSize+len(p.Payload))
	buf[0] = Version
	buf[1] = byte(p.Type)
	buf[2] = p.Flags
	buf[3] = HeaderSize
	binary.BigEndian.PutUint64(buf[4:12], p.SessionID)
	binary.BigEndian.PutUint64(buf[12:20], p.PacketID)
	binary.BigEndian.PutUint64(buf[20:28], p.BlockID)
	binary.BigEndian.PutUint16(buf[28:30], p.FragIndex)
	binary.BigEndian.PutUint16(buf[30:32], p.FragCount)
	binary.BigEndian.PutUint64(buf[32:40], p.AckBase)
	binary.BigEndian.PutUint64(buf[40:48], p.AckBitmap)
	binary.BigEndian.PutUint32(buf[48:52], p.SendTSMillis)
	binary.BigEndian.PutUint16(buf[52:54], uint16(len(p.Payload)))
	copy(buf[HeaderSize:], p.Payload)
	return buf, nil
}

func DecodeDataPacket(buf []byte) (DataPacket, error) {
	if len(buf) < HeaderSize {
		return DataPacket{}, ErrShortDataFrame
	}
	if buf[0] != Version {
		return DataPacket{}, fmt.Errorf("%w: version %d", ErrBadDataFrame, buf[0])
	}
	if int(buf[3]) != HeaderSize {
		return DataPacket{}, fmt.Errorf("%w: header_len %d", ErrBadDataFrame, buf[3])
	}
	payloadLen := int(binary.BigEndian.Uint16(buf[52:54]))
	if payloadLen > MaxBlockPayload {
		return DataPacket{}, ErrPayloadTooLarge
	}
	if len(buf) != HeaderSize+payloadLen {
		return DataPacket{}, fmt.Errorf("%w: payload_len %d, frame_len %d", ErrBadDataFrame, payloadLen, len(buf))
	}
	p := DataPacket{
		Version:      buf[0],
		Type:         DataType(buf[1]),
		Flags:        buf[2],
		SessionID:    binary.BigEndian.Uint64(buf[4:12]),
		PacketID:     binary.BigEndian.Uint64(buf[12:20]),
		BlockID:      binary.BigEndian.Uint64(buf[20:28]),
		FragIndex:    binary.BigEndian.Uint16(buf[28:30]),
		FragCount:    binary.BigEndian.Uint16(buf[30:32]),
		AckBase:      binary.BigEndian.Uint64(buf[32:40]),
		AckBitmap:    binary.BigEndian.Uint64(buf[40:48]),
		SendTSMillis: binary.BigEndian.Uint32(buf[48:52]),
		Payload:      buf[HeaderSize:],
	}
	if p.FragCount == 0 || p.FragIndex >= p.FragCount {
		return DataPacket{}, fmt.Errorf("%w: frag %d/%d", ErrBadDataFrame, p.FragIndex, p.FragCount)
	}
	return p, nil
}

func FragmentIP(packet []byte) (frags [][]byte) {
	if len(packet) <= MaxBlockPayload {
		return [][]byte{packet}
	}
	for len(packet) > 0 {
		n := len(packet)
		if n > MaxBlockPayload {
			n = MaxBlockPayload
		}
		frags = append(frags, packet[:n])
		packet = packet[n:]
	}
	return frags
}

// Envelope is the common control-channel frame. Payload is JSON. Binary
// stream frames are represented by Type "STREAM_BINARY" and Stream; Payload
// is empty in that case.
type Envelope struct {
	Type      string          `json:"type"`
	RequestID uint32          `json:"request_id,omitempty"`
	Payload   json.RawMessage `json:"payload,omitempty"`
	Stream    *StreamFrame    `json:"-"`
}

type HelloAck struct {
	Nonce        string `json:"nonce"`
	Version      int    `json:"version"`
	AuthRequired bool   `json:"auth_required"`
}

type AuthRequest struct {
	Token     string `json:"token"`
	DeviceID  string `json:"device_id,omitempty"`
	PublicKey string `json:"public_key"`
	Signature string `json:"signature"`
}

type SessionReady struct {
	SessionID        uint64   `json:"session_id"`
	DataAddr         string   `json:"data_addr"`
	LANDataAddr      string   `json:"lan_data_addr,omitempty"`
	DataToken        string   `json:"data_token"`
	TunnelIPv4       string   `json:"tunnel_ipv4,omitempty"`
	TunnelIPv6       string   `json:"tunnel_ipv6,omitempty"`
	TunnelIPv4Prefix string   `json:"tunnel_ipv4_prefix,omitempty"`
	TunnelIPv4CIDR   string   `json:"tunnel_ipv4_cidr,omitempty"`
	GatewayIPv4      string   `json:"gateway_ipv4,omitempty"`
	GatewayIPv6      string   `json:"gateway_ipv6,omitempty"`
	MTU              int      `json:"mtu"`
	Routes           []string `json:"routes,omitempty"`
	ExpiresAt        string   `json:"expires_at"`
	IPLeaseExpiresAt string   `json:"ip_lease_expires_at,omitempty"`
}

// SessionRefresh is sent when the server extends an active session's TTL.
// DataToken intentionally remains valid for the lifetime of the session; the
// server checks the session expiry at data bind time instead of trusting the
// creation-time timestamp embedded in the token.
type SessionRefresh struct {
	ExpiresAt string `json:"expires_at"`
}

type Stats struct {
	SessionID          uint64 `json:"session_id"`
	SentPackets        uint64 `json:"sent_packets"`
	SentBlocks         uint64 `json:"sent_blocks"`
	ReceivedBlocks     uint64 `json:"received_blocks"`
	AckedBlocks        uint64 `json:"acked_blocks"`
	ReassembledPackets uint64 `json:"reassembled_packets"`
	EgressedPackets    uint64 `json:"egressed_packets"`
	RemotePackets      uint64 `json:"remote_packets"`
	DuplicateBlocks    uint64 `json:"duplicate_blocks"`
	LostBlocks         uint64 `json:"lost_blocks"`
	RepairedBlocks     uint64 `json:"repaired_blocks"`
	ReassemblyDrops    uint64 `json:"reassembly_drops"`
	QueueDrops         uint64 `json:"queue_drops"`
	BytesSent          uint64 `json:"bytes_sent"`
	BytesReceived      uint64 `json:"bytes_received"`
	AckBase            uint64 `json:"ack_base"`
	AckBitmap          uint64 `json:"ack_bitmap"`
	InvalidSource      uint64 `json:"invalid_source"`
}

type ErrorMessage struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

func WriteControlFrame(w io.Writer, env Envelope) error {
	body, err := json.Marshal(env)
	if err != nil {
		return err
	}
	if len(body) > MaxControlFrame {
		return fmt.Errorf("cbp: control frame exceeds %d bytes", MaxControlFrame)
	}
	frame := make([]byte, 4+len(body))
	binary.BigEndian.PutUint32(frame[:4], uint32(len(body)))
	copy(frame[4:], body)
	// One Write keeps header and body in the same TLS record. Two Writes
	// produce two records, adding a round-trip-sized latency to every stream
	// frame on the control connection.
	_, err = w.Write(frame)
	return err
}

func ReadControlFrame(r io.Reader) (Envelope, error) {
	head := make([]byte, 4)
	if _, err := io.ReadFull(r, head); err != nil {
		return Envelope{}, err
	}
	n := binary.BigEndian.Uint32(head)
	if n == 0 || n > MaxControlFrame {
		return Envelope{}, fmt.Errorf("cbp: invalid control frame length %d", n)
	}
	body := make([]byte, n)
	if _, err := io.ReadFull(r, body); err != nil {
		return Envelope{}, err
	}
	if len(body) >= 10 && body[0] == StreamFrameMarker {
		frame, err := DecodeStreamFrame(body)
		if err != nil {
			return Envelope{}, err
		}
		return Envelope{Type: "STREAM_BINARY", Stream: &frame}, nil
	}
	var env Envelope
	if err := json.Unmarshal(body, &env); err != nil {
		return Envelope{}, fmt.Errorf("cbp: decode control frame: %w", err)
	}
	if env.Type == "" {
		return Envelope{}, errors.New("cbp: control frame missing type")
	}
	return env, nil
}

func MarshalPayload(v any) (json.RawMessage, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	return json.RawMessage(b), nil
}

func UnmarshalPayload(raw json.RawMessage, v any) error {
	if len(raw) == 0 {
		return errors.New("cbp: empty payload")
	}
	return json.Unmarshal(raw, v)
}

func UnixMillis(t time.Time) uint32 {
	if t.IsZero() {
		return 0
	}
	ms := t.UnixNano() / int64(time.Millisecond)
	if ms < 0 {
		return 0
	}
	if ms > math.MaxUint32 {
		return math.MaxUint32
	}
	return uint32(ms)
}

// ResolveRequest asks the node to resolve one hostname at the exit point.
// The client never sends the hostname to its local resolver; the node uses
// its upstream resolver and returns the addresses over the authenticated
// control stream.
type ResolveRequest struct {
	ID   uint64 `json:"id"`
	Host string `json:"host"`
}

type ResolveResponse struct {
	ID        uint64   `json:"id"`
	Addresses []string `json:"addresses,omitempty"`
	Error     string   `json:"error,omitempty"`
}
