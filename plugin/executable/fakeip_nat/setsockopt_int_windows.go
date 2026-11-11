//go:build windows

package fakeipnat

import "syscall"

// setsockoptInt wraps the Windows signature, where the first argument is a
// syscall.Handle instead of an int.
func setsockoptInt(fd uintptr, level, opt, value int) error {
	return syscall.SetsockoptInt(syscall.Handle(fd), level, opt, value)
}
