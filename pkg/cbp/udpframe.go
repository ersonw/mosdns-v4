package cbp

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
)

// UDP frame layout carried inside one CBP STREAM_DATA frame:
//
//	byte 0      address type (1 = IPv4, 2 = IPv6)
//	bytes 1..N  IP address
//	bytes N+1..N+2  destination port, big endian
//	bytes N+3..  UDP payload
//
// One frame is exactly one datagram. The address is needed because a CBP
// UDP association is unconnected and must be able to send to every remote
// endpoint a browser's WebRTC/QUIC stack uses.
const (
	UDPFrameIPv4 byte = 1
	UDPFrameIPv6 byte = 2

	maxUDPPayload = 65507
)

var ErrBadUDPFrame = errors.New("cbp: invalid UDP frame")

// EncodeUDPFrame serializes one UDP datagram and its destination address.
func EncodeUDPFrame(addr *net.UDPAddr, payload []byte) ([]byte, error) {
	if addr == nil || addr.IP == nil {
		return nil, fmt.Errorf("%w: address is required", ErrBadUDPFrame)
	}
	if len(payload) > maxUDPPayload {
		return nil, fmt.Errorf("%w: UDP payload is %d bytes", ErrBadUDPFrame, len(payload))
	}
	var head int
	var atyp byte
	if ip4 := addr.IP.To4(); ip4 != nil {
		atyp = UDPFrameIPv4
		head = 1 + 4 + 2
	} else if ip16 := addr.IP.To16(); ip16 != nil {
		atyp = UDPFrameIPv6
		head = 1 + 16 + 2
	} else {
		return nil, fmt.Errorf("%w: unsupported IP address", ErrBadUDPFrame)
	}
	if frameLen := head + len(payload); frameLen > MaxStreamChunk {
		return nil, fmt.Errorf("%w: frame is %d bytes", ErrBadUDPFrame, frameLen)
	}
	frame := make([]byte, head+len(payload))
	frame[0] = atyp
	if atyp == UDPFrameIPv4 {
		copy(frame[1:5], addr.IP.To4())
		binary.BigEndian.PutUint16(frame[5:7], uint16(addr.Port))
	} else {
		copy(frame[1:17], addr.IP.To16())
		binary.BigEndian.PutUint16(frame[17:19], uint16(addr.Port))
	}
	copy(frame[head:], payload)
	return frame, nil
}

// DecodeUDPFrame parses one address-prefixed datagram frame.
func DecodeUDPFrame(frame []byte) (*net.UDPAddr, []byte, error) {
	if len(frame) < 1 {
		return nil, nil, fmt.Errorf("%w: empty frame", ErrBadUDPFrame)
	}
	switch frame[0] {
	case UDPFrameIPv4:
		if len(frame) < 1+4+2 {
			return nil, nil, fmt.Errorf("%w: short IPv4 frame", ErrBadUDPFrame)
		}
		addr := &net.UDPAddr{
			IP:   net.IP(append([]byte(nil), frame[1:5]...)),
			Port: int(binary.BigEndian.Uint16(frame[5:7])),
		}
		return addr, frame[7:], nil
	case UDPFrameIPv6:
		if len(frame) < 1+16+2 {
			return nil, nil, fmt.Errorf("%w: short IPv6 frame", ErrBadUDPFrame)
		}
		addr := &net.UDPAddr{
			IP:   net.IP(append([]byte(nil), frame[1:17]...)),
			Port: int(binary.BigEndian.Uint16(frame[17:19])),
		}
		return addr, frame[19:], nil
	default:
		return nil, nil, fmt.Errorf("%w: address type %d", ErrBadUDPFrame, frame[0])
	}
}
