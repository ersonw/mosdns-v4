//go:build !linux

package asn_tun

import "syscall"

func applySocketOptions(syscall.RawConn, uint32, string) error {
	return nil
}
