package cbp

import (
	"bytes"
	"compress/flate"
	"fmt"
	"io"
)

// CompressIP compresses a raw IP packet with raw DEFLATE. It returns the
// original bytes and false when compression does not save space, so both sides
// always agree on whether the FlagCompressed bit is set.
func CompressIP(packet []byte) ([]byte, bool) {
	if len(packet) < 64 {
		return packet, false
	}
	var buf bytes.Buffer
	w, err := flate.NewWriter(&buf, flate.BestSpeed)
	if err != nil {
		return packet, false
	}
	if _, err := w.Write(packet); err != nil {
		_ = w.Close()
		return packet, false
	}
	if err := w.Close(); err != nil {
		return packet, false
	}
	if buf.Len() >= len(packet) {
		return packet, false
	}
	return buf.Bytes(), true
}

// DecompressIP restores a compressed payload.
func DecompressIP(packet []byte) ([]byte, error) {
	r := flate.NewReader(bytes.NewReader(packet))
	defer r.Close()
	out, err := io.ReadAll(io.LimitReader(r, MaxIPPacketBytes+1))
	if err != nil {
		return nil, fmt.Errorf("cbp: decompress: %w", err)
	}
	if len(out) > MaxIPPacketBytes {
		return nil, ErrPacketTooLarge
	}
	return out, nil
}
