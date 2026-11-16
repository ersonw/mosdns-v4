package cbp

import (
	"bytes"
	"encoding/binary"
	"testing"
	"time"
)

func TestDataPacketRoundTrip(t *testing.T) {
	in := DataPacket{
		Type:         DataTypeData,
		Flags:        FlagIPv4 | FlagLastFragment,
		SessionID:    0x1122334455667788,
		PacketID:     7,
		BlockID:      9,
		FragIndex:    1,
		FragCount:    3,
		AckBase:      42,
		AckBitmap:    0x8000000000000001,
		SendTSMillis: 123456789,
		Payload:      []byte("payload"),
	}
	raw, err := in.Encode()
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	if len(raw) != HeaderSize+len(in.Payload) {
		t.Fatalf("frame length = %d, want %d", len(raw), HeaderSize+len(in.Payload))
	}
	out, err := DecodeDataPacket(raw)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if out.Type != in.Type || out.SessionID != in.SessionID || out.PacketID != in.PacketID ||
		out.BlockID != in.BlockID || out.FragIndex != in.FragIndex || out.FragCount != in.FragCount ||
		out.AckBase != in.AckBase || out.AckBitmap != in.AckBitmap || out.SendTSMillis != in.SendTSMillis ||
		out.Flags != in.Flags {
		t.Fatalf("header mismatch: %+v", out)
	}
	if !bytes.Equal(out.Payload, in.Payload) {
		t.Fatalf("payload mismatch: %q", out.Payload)
	}
	// payload_len is the last field of the 54-byte header, and header_len
	// records the header size itself; both are read by the edge.
	if binary.BigEndian.Uint16(raw[HeaderSize-2:HeaderSize]) != uint16(len(in.Payload)) {
		t.Fatalf("payload_len field is not at the documented offset")
	}
	if raw[3] != uint8(HeaderSize) {
		t.Fatalf("header_len = %d, want %d", raw[3], HeaderSize)
	}
}

func TestDecodeRejectsShortFrame(t *testing.T) {
	if _, err := DecodeDataPacket(make([]byte, HeaderSize-1)); err == nil {
		t.Fatal("short frame decoded without error")
	}
}

func TestFragmentAndReassemble(t *testing.T) {
	packet := make([]byte, 2600)
	for i := range packet {
		packet[i] = byte(i)
	}
	frags := FragmentIP(packet)
	if len(frags) == 0 {
		t.Fatal("no fragments")
	}
	for i, f := range frags {
		if len(f) > MaxBlockPayload {
			t.Fatalf("fragment %d is %d bytes, over %d", i, len(f), MaxBlockPayload)
		}
	}
	r := NewReassembler(DefaultMaxPacketsInFlight, DefaultReassemblyTimeout)
	var whole []byte
	for i, f := range frags {
		pkt := DataPacket{
			Type:      DataTypeData,
			PacketID:  1,
			BlockID:   uint64(i),
			FragIndex: uint16(i),
			FragCount: uint16(len(frags)),
			Payload:   f,
		}
		ip, complete := r.Add(pkt)
		if complete {
			whole = ip
		}
	}
	if whole == nil {
		t.Fatal("packet never completed")
	}
	if !bytes.Equal(whole, packet) {
		t.Fatalf("reassembled %d bytes, want %d", len(whole), len(packet))
	}
}

func TestCompressRoundTrip(t *testing.T) {
	packet := make([]byte, 900)
	binary.BigEndian.PutUint16(packet[2:4], uint16(len(packet)))
	// A highly repetitive payload must round-trip through deflate.
	for i := 20; i < len(packet); i++ {
		packet[i] = byte('a' + i%3)
	}
	wire, compressed := CompressIP(packet)
	if !compressed {
		t.Skip("payload did not compress; nothing to verify")
	}
	if len(wire) >= len(packet) {
		t.Fatalf("compressed length %d not below %d", len(wire), len(packet))
	}
	out, err := DecompressIP(wire)
	if err != nil {
		t.Fatalf("decompress: %v", err)
	}
	if !bytes.Equal(out, packet) {
		t.Fatal("compressed packet did not round-trip")
	}
}

func TestAckTrackerReportsGap(t *testing.T) {
	a := NewAckTracker()
	for _, id := range []uint64{0, 1, 2, 4} {
		a.Observe(id)
	}
	base, bitmap := a.Snapshot()
	// Block ids start at 0, so 0..2 are contiguous and 3 is the first missing
	// id; 4 sits one slot above it and must be visible in the bitmap.
	if base != 3 {
		t.Fatalf("base = %d, want 3", base)
	}
	if bitmap&1 != 0 {
		t.Fatalf("bitmap marks the missing id as received: %#x", bitmap)
	}
	if bitmap&2 == 0 {
		t.Fatalf("bitmap lost the block after the gap: %#x", bitmap)
	}
	if a.Observe(1) {
		t.Fatal("duplicate block reported as new")
	}
}

func TestSendWindowTransmitsOnce(t *testing.T) {
	writes := make(chan DataPacket, 4)
	w := NewSendWindow(SendWindowConfig{
		Write: func(p DataPacket) error {
			writes <- p
			return nil
		},
	})
	w.Start()
	defer w.Close()
	if !w.Push(99, 1, []uint64{5}, []uint8{FlagIPv4 | FlagLastFragment}, [][]byte{[]byte("x")}) {
		t.Fatal("push rejected")
	}
	select {
	case p := <-writes:
		if p.SessionID != 99 || p.PacketID != 1 || p.BlockID != 5 {
			t.Fatalf("unexpected frame: %+v", p)
		}
	case <-time.After(time.Second):
		t.Fatal("window never transmitted the packet")
	}
}
