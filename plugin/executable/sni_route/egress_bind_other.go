//go:build !linux

package sni_route

import "syscall"

func applySocketOptions(syscall.RawConn, uint32, string) error {
	return nil
}
