//go:build !windows

package fakeipnat

import "syscall"

// setsockoptInt hides the platform difference of syscall.SetsockoptInt: BSD and
// Linux take the raw descriptor, Windows takes a syscall.Handle.
func setsockoptInt(fd uintptr, level, opt, value int) error {
	return syscall.SetsockoptInt(int(fd), level, opt, value)
}
