package fakeipnat

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strconv"
)

// appendProxyAddr appends the SOCKS5 address form (ATYP | ADDR | PORT). Both
// the socks5 and the trojan wire formats carry the target this way.
func appendProxyAddr(buf []byte, addr string) ([]byte, error) {
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, fmt.Errorf("invalid target %q: %w", addr, err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port < 0 || port > 65535 {
		return nil, fmt.Errorf("invalid target port %q", portStr)
	}
	if ip := net.ParseIP(host); ip != nil {
		if ip4 := ip.To4(); ip4 != nil {
			buf = append(buf, 0x01, ip4[0], ip4[1], ip4[2], ip4[3])
		} else {
			buf = append(buf, 0x04)
			buf = append(buf, ip.To16()...)
		}
	} else {
		if len(host) > 255 {
			return nil, fmt.Errorf("target host %q is too long for a proxy address", host)
		}
		buf = append(buf, 0x03, byte(len(host)))
		buf = append(buf, host...)
	}
	return append(buf, byte(port>>8), byte(port&0xFF)), nil
}

// readProxyAddr reads one SOCKS5 address form and returns it as "host:port".
func readProxyAddr(r io.Reader) (string, error) {
	var atyp [1]byte
	if _, err := io.ReadFull(r, atyp[:]); err != nil {
		return "", err
	}
	var host string
	switch atyp[0] {
	case 0x01:
		var b [4]byte
		if _, err := io.ReadFull(r, b[:]); err != nil {
			return "", err
		}
		host = net.IP(b[:]).String()
	case 0x04:
		var b [16]byte
		if _, err := io.ReadFull(r, b[:]); err != nil {
			return "", err
		}
		host = net.IP(b[:]).String()
	case 0x03:
		var l [1]byte
		if _, err := io.ReadFull(r, l[:]); err != nil {
			return "", err
		}
		name := make([]byte, int(l[0]))
		if _, err := io.ReadFull(r, name); err != nil {
			return "", err
		}
		host = string(name)
	default:
		return "", fmt.Errorf("unsupported address type %#x", atyp[0])
	}
	var p [2]byte
	if _, err := io.ReadFull(r, p[:]); err != nil {
		return "", err
	}
	return net.JoinHostPort(host, strconv.Itoa(int(binary.BigEndian.Uint16(p[:])))), nil
}
