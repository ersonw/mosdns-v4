package sni_route

import (
	"encoding/binary"
	"strings"
)

// helloResult is what a bounded read of the first bytes of a TLS connection
// concluded.
type helloResult int

const (
	// helloNeedMore means the buffer holds a plausible TLS ClientHello but it
	// is not complete yet (a record was split, or the extensions did not fit).
	helloNeedMore helloResult = iota
	// helloInvalid means the bytes cannot be a ClientHello, or the handshake
	// finished without a server_name extension.
	helloInvalid
	// helloOK means a server name was parsed.
	helloOK
)

const (
	tlsRecordHeaderLen = 5
	tlsRecordTypeHello = 0x16
	tlsHandshakeClient = 0x01
	maxHelloBytes      = 16 << 10
)

// parseClientHelloSNI extracts the server_name from the first ClientHello in
// data. It understands a handshake split over more than one TLS record, which
// is what a large ClientHello (many cipher suites, GREASE, ECH hints) looks
// like on the wire.
//
// The parser is deliberately small: it only needs the SNI, not a handshake, and
// an unparseable buffer must fall back to a byte-transparent relay rather than
// drop the connection.
func parseClientHelloSNI(data []byte) (string, helloResult) {
	if len(data) == 0 {
		return "", helloNeedMore
	}
	if data[0] != tlsRecordTypeHello {
		return "", helloInvalid
	}

	var handshake []byte
	pos := 0
	for {
		if pos == len(data) {
			// Every complete record so far was consumed, but the handshake is
			// still short: the peer has more to send.
			return "", helloNeedMore
		}
		if len(data)-pos < tlsRecordHeaderLen {
			return "", helloNeedMore
		}
		recType := data[pos]
		recLen := int(binary.BigEndian.Uint16(data[pos+3 : pos+5]))
		if recLen <= 0 || recLen > maxHelloBytes {
			return "", helloInvalid
		}
		recEnd := pos + tlsRecordHeaderLen + recLen
		if recEnd > len(data) {
			return "", helloNeedMore
		}
		if recType != tlsRecordTypeHello {
			// A non-handshake record before the ClientHello is complete means
			// this is not the start of a TLS handshake we can route.
			return "", helloInvalid
		}
		handshake = append(handshake, data[pos+tlsRecordHeaderLen:recEnd]...)
		pos = recEnd

		if len(handshake) < 4 {
			continue
		}
		if handshake[0] != tlsHandshakeClient {
			return "", helloInvalid
		}
		hsLen := int(handshake[1])<<16 | int(handshake[2])<<8 | int(handshake[3])
		if hsLen <= 0 || hsLen > maxHelloBytes {
			return "", helloInvalid
		}
		if len(handshake) < 4+hsLen {
			continue
		}
		return parseClientHelloBody(handshake[4 : 4+hsLen])
	}
}

func parseClientHelloBody(body []byte) (string, helloResult) {
	// legacy_version(2) random(32) session_id_len(1) session_id cipher_suites_len(2)
	// cipher_suites compression_len(1) compression extensions_len(2) extensions
	const fixed = 2 + 32 + 1
	if len(body) < fixed {
		return "", helloInvalid
	}
	pos := fixed
	sessionLen := int(body[pos-1])
	pos += sessionLen
	if pos+2 > len(body) {
		return "", helloInvalid
	}
	cipherLen := int(binary.BigEndian.Uint16(body[pos : pos+2]))
	pos += 2 + cipherLen
	if pos+1 > len(body) {
		return "", helloInvalid
	}
	compLen := int(body[pos])
	pos += 1 + compLen
	if pos > len(body) {
		return "", helloInvalid
	}
	// A ClientHello without extensions has no SNI. It is valid TLS but cannot
	// be matched, so the relay stays byte transparent.
	if pos == len(body) {
		return "", helloInvalid
	}
	if pos+2 > len(body) {
		return "", helloInvalid
	}
	extLen := int(binary.BigEndian.Uint16(body[pos : pos+2]))
	pos += 2
	extEnd := pos + extLen
	if extEnd > len(body) {
		return "", helloInvalid
	}

	for pos+4 <= extEnd {
		extType := binary.BigEndian.Uint16(body[pos : pos+2])
		extSize := int(binary.BigEndian.Uint16(body[pos+2 : pos+4]))
		pos += 4
		if pos+extSize > extEnd {
			return "", helloInvalid
		}
		if extType == 0x0000 {
			name, ok := parseServerNameExtension(body[pos : pos+extSize])
			if !ok {
				return "", helloInvalid
			}
			return name, helloOK
		}
		pos += extSize
	}
	return "", helloInvalid
}

func parseServerNameExtension(ext []byte) (string, bool) {
	if len(ext) < 2 {
		return "", false
	}
	listLen := int(binary.BigEndian.Uint16(ext[:2]))
	if listLen <= 0 || 2+listLen > len(ext) {
		return "", false
	}
	pos := 2
	end := 2 + listLen
	for pos+3 <= end {
		nameType := ext[pos]
		nameLen := int(binary.BigEndian.Uint16(ext[pos+1 : pos+3]))
		pos += 3
		if nameLen <= 0 || pos+nameLen > end {
			return "", false
		}
		if nameType == 0 {
			name := strings.TrimSpace(string(ext[pos : pos+nameLen]))
			name = strings.TrimSuffix(name, ".")
			if name == "" {
				return "", false
			}
			return strings.ToLower(name), true
		}
		pos += nameLen
	}
	return "", false
}
