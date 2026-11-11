package radius

import (
	"crypto/hmac"
	"crypto/md5"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
)

// Packet codes, RFC 2865 / RFC 2866.
const (
	codeAccessRequest      = 1
	codeAccessAccept       = 2
	codeAccessReject       = 3
	codeAccountingRequest  = 4
	codeAccountingResponse = 5
	codeAccessChallenge    = 11
)

// Attribute types this server reads or writes.
const (
	attrUserName            = 1
	attrUserPassword        = 2
	attrCHAPPassword        = 3
	attrNASIPAddress        = 4
	attrNASPort             = 5
	attrServiceType         = 6
	attrFramedIPAddress     = 8
	attrReplyMessage        = 18
	attrState               = 24
	attrVendorSpecific      = 26
	attrNASIdentifier       = 32
	attrProxyState          = 33
	// RFC 2866 numbering. Note the split: 42/43 are the byte counters, while
	// 46/47 are the packet counters, which this server does not read.
	attrAcctStatusType      = 40
	attrAcctInputOctets     = 42
	attrAcctOutputOctets    = 43
	attrAcctSessionID       = 44
	attrAcctSessionTime     = 45
	attrMessageAuthenticator = 80
)

// Accounting status values, RFC 2866 §5.
const (
	acctStatusStart   = 1
	acctStatusStop    = 2
	acctStatusInterim = 3
	acctStatusAlive   = 4
	acctStatusStart2  = 15 // "Start" with a different accounting-request type
)

const (
	radiusHeaderLen = 20
	radiusMaxPacket = 4096
	radiusAuthLen   = 16
)

var (
	errPacketTooShort  = errors.New("radius: packet shorter than the 20 byte header")
	errBadLength       = errors.New("radius: length field does not match the datagram")
	errBadAttribute    = errors.New("radius: truncated attribute")
	errNoUserPassword  = errors.New("radius: no user-password attribute")
	errBadUserPassword = errors.New("radius: malformed user-password attribute")
)

// attribute is one TLV inside a packet.
type attribute struct {
	typ   byte
	value []byte
}

// packet is a decoded RADIUS message.
type packet struct {
	code          byte
	id            byte
	authenticator [radiusAuthLen]byte
	attrs         []attribute
}

func (p *packet) get(typ byte) ([]byte, bool) {
	for _, a := range p.attrs {
		if a.typ == typ {
			return a.value, true
		}
	}
	return nil, false
}

func (p *packet) getString(typ byte) string {
	if v, ok := p.get(typ); ok {
		return string(v)
	}
	return ""
}

func (p *packet) getUint32(typ byte) (uint32, bool) {
	v, ok := p.get(typ)
	if !ok || len(v) != 4 {
		return 0, false
	}
	return binary.BigEndian.Uint32(v), true
}

// parsePacket decodes a datagram. Trailing bytes past the declared length are
// ignored, which is what RFC 2865 tells a server to do with padding.
func parsePacket(b []byte) (*packet, error) {
	if len(b) < radiusHeaderLen {
		return nil, errPacketTooShort
	}
	declared := int(binary.BigEndian.Uint16(b[2:4]))
	if declared < radiusHeaderLen || declared > len(b) {
		return nil, errBadLength
	}
	b = b[:declared]

	p := &packet{code: b[0], id: b[1]}
	copy(p.authenticator[:], b[4:radiusHeaderLen])

	rest := b[radiusHeaderLen:]
	for len(rest) > 0 {
		if len(rest) < 2 {
			return nil, errBadAttribute
		}
		l := int(rest[1])
		if l < 2 || l > len(rest) {
			return nil, errBadAttribute
		}
		p.attrs = append(p.attrs, attribute{typ: rest[0], value: append([]byte(nil), rest[2:l]...)})
		rest = rest[l:]
	}
	return p, nil
}

// encode serializes the packet. response authenticator is filled in when a
// request authenticator is supplied; pass nil for requests built by tests.
func (p *packet) encode(secret []byte, requestAuth []byte) []byte {
	b := make([]byte, radiusHeaderLen, radiusHeaderLen+64*4)
	b[0] = p.code
	b[1] = p.id
	for _, a := range p.attrs {
		vlen := len(a.value)
		if vlen > 253 {
			vlen = 253 // never split an attribute over two TLVs here
		}
		b = append(b, a.typ, byte(2+vlen))
		b = append(b, a.value[:vlen]...)
	}
	binary.BigEndian.PutUint16(b[2:4], uint16(len(b)))
	if requestAuth != nil {
		copy(p.authenticator[:], responseAuthenticator(b, requestAuth, secret))
	}
	copy(b[4:radiusHeaderLen], p.authenticator[:])
	return b
}

// responseAuthenticator computes MD5(code|id|length|request authenticator|
// attributes|secret), RFC 2865 §3.
func responseAuthenticator(msg []byte, requestAuth, secret []byte) []byte {
	h := md5.New()
	h.Write(msg[0:4])
	h.Write(requestAuth)
	h.Write(msg[radiusHeaderLen:])
	h.Write(secret)
	return h.Sum(nil)
}

// verifyRequestAuthenticator checks the response/accounting authenticator a
// request carries. Access-Requests use a random authenticator instead, so this
// is only for Accounting-Request (RFC 2866 §3) and server-side sanity checks.
func verifyRequestAuthenticator(p *packet, raw []byte, secret []byte) bool {
	h := md5.New()
	h.Write(raw[0:4])
	h.Write(make([]byte, radiusAuthLen)) // authenticator field is zero while hashing
	h.Write(raw[radiusHeaderLen:])
	h.Write(secret)
	return subtle.ConstantTimeCompare(h.Sum(nil), p.authenticator[:]) == 1
}

// decodeUserPassword reverses the RFC 2865 §5.2 masking.
func decodeUserPassword(enc []byte, secret []byte, auth []byte) (string, error) {
	if len(enc) == 0 || len(enc)%radiusAuthLen != 0 {
		return "", errBadUserPassword
	}
	out := make([]byte, len(enc))
	prev := auth
	for i := 0; i < len(enc); i += radiusAuthLen {
		block := xorBlock(enc[i:i+radiusAuthLen], secret, prev)
		copy(out[i:], block)
		prev = enc[i : i+radiusAuthLen]
	}
	// The plaintext is null padded to a 16 byte boundary.
	for len(out) > 0 && out[len(out)-1] == 0 {
		out = out[:len(out)-1]
	}
	return string(out), nil
}

// encodeUserPassword applies the same masking, used by tests and by any future
// client side.
func encodeUserPassword(plain, secret, auth []byte) []byte {
	pad := len(plain) % radiusAuthLen
	if pad != 0 {
		pad = radiusAuthLen - pad
	}
	buf := make([]byte, len(plain)+pad)
	copy(buf, plain)

	prev := auth
	enc := make([]byte, len(buf))
	for i := 0; i < len(buf); i += radiusAuthLen {
		block := xorBlock(buf[i:i+radiusAuthLen], secret, prev)
		copy(enc[i:], block)
		prev = enc[i : i+radiusAuthLen]
	}
	return enc
}

func xorBlock(block, secret, prev []byte) []byte {
	h := md5.New()
	h.Write(secret)
	h.Write(prev)
	digest := h.Sum(nil)
	out := make([]byte, radiusAuthLen)
	for i := 0; i < radiusAuthLen; i++ {
		out[i] = block[i] ^ digest[i]
	}
	return out
}

// verifyMessageAuthenticator checks the HMAC-MD5 attribute (RFC 3579 §3.2).
// Packets without the attribute are accepted: radcli only sends it when the
// server advertises support.
func verifyMessageAuthenticator(raw []byte, secret []byte) (present bool, ok bool) {
	p, err := parsePacket(raw)
	if err != nil {
		return false, false
	}
	v, present := p.get(attrMessageAuthenticator)
	if !present {
		return false, true
	}
	if len(v) != 16 {
		return true, false
	}
	mac := hmacMD5(raw, secret)
	return true, hmac.Equal(mac, v)
}

// setMessageAuthenticator recomputes the attribute after the packet is fully
// built. The attribute value must already be present (zeros are fine).
func setMessageAuthenticator(raw []byte, secret []byte) bool {
	rest := raw[radiusHeaderLen:]
	for i := 0; i+2 <= len(rest); {
		l := int(rest[i+1])
		if l < 2 || i+l > len(rest) {
			return false
		}
		if rest[i] == attrMessageAuthenticator {
			if l != 18 {
				return false
			}
			for j := 0; j < 16; j++ {
				rest[i+2+j] = 0
			}
			sum := hmacMD5(raw, secret)
			copy(rest[i+2:i+18], sum)
			return true
		}
		i += l
	}
	return false
}

// hmacMD5 hashes the whole packet with HMAC-MD5, keyed by the shared secret.
func hmacMD5(raw, secret []byte) []byte {
	var h hash.Hash = hmac.New(md5.New, secret)
	h.Write(raw)
	return h.Sum(nil)
}

// parseMessageAuthenticator returns the attribute value with the zeroed form
// of the packet, so callers can compare against their own HMAC.
func parseMessageAuthenticatorAttr(raw []byte) ([]byte, bool, error) {
	p, err := parsePacket(raw)
	if err != nil {
		return nil, false, err
	}
	v, ok := p.get(attrMessageAuthenticator)
	return v, ok, nil
}

func buildAccessRequest(secret []byte, id byte, attrs []attribute) []byte {
	p := &packet{code: codeAccessRequest, id: id, attrs: attrs}
	return p.encode(secret, nil)
}

func buildAccessAccept(request *packet, secret []byte, attrs []attribute) []byte {
	p := &packet{code: codeAccessAccept, id: request.id, attrs: attrs}
	return p.encode(secret, request.authenticator[:])
}

func buildAccessReject(request *packet, secret []byte, reason string) []byte {
	var attrs []attribute
	if reason != "" {
		attrs = append(attrs, attribute{typ: attrReplyMessage, value: []byte(reason)})
	}
	p := &packet{code: codeAccessReject, id: request.id, attrs: attrs}
	return p.encode(secret, request.authenticator[:])
}

func buildAccountingResponse(request *packet, secret []byte) []byte {
	p := &packet{code: codeAccountingResponse, id: request.id}
	return p.encode(secret, request.authenticator[:])
}

// requireAttr is a tiny helper for clearer error messages in the server.
func requireAttr(p *packet, typ byte, name string) ([]byte, error) {
	v, ok := p.get(typ)
	if !ok {
		return nil, fmt.Errorf("radius: request has no %s", name)
	}
	return v, nil
}
