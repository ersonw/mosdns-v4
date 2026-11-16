// Package cbp is a client for the CustomBrowser Packet Protocol (CBP/1).
//
// CBP carries raw IPv4/IPv6 packets - TCP, UDP and ICMP alike - between a
// client and an edge server. It has two planes:
//
//   - control: TCP + TLS 1.3, ALPN cbp-control/1, length-prefixed JSON frames.
//   - data: QUIC + TLS 1.3, ALPN cbp-data/1, QUIC DATAGRAM frames that carry
//     one fragment of a raw IP packet per datagram.
//
// The server decrypts nothing on the inner protocols: it reassembles the IP
// packets and writes them to a real TUN device, so the whole protocol set is
// available without a per-protocol implementation on this side either. That is
// why this package is the only proxy outlet whose transport is not a TCP
// stream: the caller feeds it IP packets and gets IP packets back.
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
	// Version is the wire version written in every data frame.
	Version = 1

	// HeaderSize is the fixed size of a CBP data frame.
	HeaderSize = 54

	// MaxBlockPayload keeps one datagram inside the IPv6 minimum MTU.
	MaxBlockPayload = 1100

	// MaxControlFrame guards the control channel against unbounded frames.
	MaxControlFrame = 1 << 20

	ALPNControl = "cbp-control/1"
	ALPNData    = "cbp-data/1"

	// StreamFrameMarker distinguishes a binary stream frame from the JSON
	// control envelope. This client never opens streams, but the server may
	// still send one, so the reader has to recognise the marker.
	StreamFrameMarker byte = 0xC1
)

// DataType is the frame type of one CBP datagram.
type DataType uint8

const (
	DataTypeData DataType = iota + 1
	DataTypeACK
	DataTypeBind
	DataTypePing
	DataTypeRepair
)

// Frame flags.
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

// DataPacket is one on-wire datagram: a fragment of a raw IP packet, or a
// bind/ack/repair control datagram. ACK fields are piggybacked on every frame.
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

// Encode writes the fixed header followed by the payload.
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

// DecodeDataPacket parses one datagram and validates its header.
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

// FragmentIP splits one IP packet into block-sized fragments.
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

// Envelope is one control-channel frame. Payload is JSON.
type Envelope struct {
	Type      string          `json:"type"`
	RequestID uint32          `json:"request_id,omitempty"`
	Payload   json.RawMessage `json:"payload,omitempty"`
	Stream    *StreamFrame    `json:"-"`
}

// HelloAck is the server's first frame: a nonce to sign plus the version.
type HelloAck struct {
	Nonce        string `json:"nonce"`
	Version      int    `json:"version"`
	AuthRequired bool   `json:"auth_required"`
}

// AuthRequest authenticates the deployment token and the client key.
type AuthRequest struct {
	Token     string `json:"token"`
	DeviceID  string `json:"device_id,omitempty"`
	PublicKey string `json:"public_key"`
	Signature string `json:"signature"`
}

// SessionReady is the accepted session: data address, tunnel addresses, MTU.
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

// SessionRefresh extends an active session's lifetime.
type SessionRefresh struct {
	ExpiresAt string `json:"expires_at"`
}

// ErrorMessage is a control-plane failure.
type ErrorMessage struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

// ServerStats is the authoritative counter frame sent every few seconds.
type ServerStats struct {
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
	AckBase            uint64 `json:"ack_base"`
	AckBitmap          uint64 `json:"ack_bitmap"`
}

// StreamFrame is a binary stream frame. This client does not open streams, so
// a decoded frame is only ever discarded.
type StreamFrame struct {
	Kind     byte
	StreamID uint64
	Credit   uint32
	Data     []byte
}

// WriteControlFrame writes exactly one length-prefixed JSON frame. Header and
// body go out in one Write so they share one TLS record.
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
	_, err = w.Write(frame)
	return err
}

// ReadControlFrame reads one frame. A binary stream frame is surfaced as
// Type "STREAM_BINARY" so the caller can ignore it explicitly.
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
		return Envelope{Type: "STREAM_BINARY", Stream: &StreamFrame{Kind: body[1], StreamID: binary.BigEndian.Uint64(body[2:10])}}, nil
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

// MarshalPayload encodes a control payload.
func MarshalPayload(v any) (json.RawMessage, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	return json.RawMessage(b), nil
}

// UnmarshalPayload decodes a control payload.
func UnmarshalPayload(raw json.RawMessage, v any) error {
	if len(raw) == 0 {
		return errors.New("cbp: empty payload")
	}
	return json.Unmarshal(raw, v)
}

// UnixMillis converts a timestamp to the frame's millisecond field.
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

// streamFramePool is kept for symmetry with the reference implementation: a
// future stream client reuses one buffer per frame.
var streamFramePool = sync.Pool{New: func() any { b := make([]byte, 0); return &b }}
