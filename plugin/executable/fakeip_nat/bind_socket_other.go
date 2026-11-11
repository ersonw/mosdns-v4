//go:build !linux && !darwin

package fakeipnat

import "errors"

// errDeviceBindUnsupported reports a platform without a way to pin a socket to
// an interface. The caller keeps the socket unbound and says so once, instead of
// silently ignoring a configured next_hop_dev.
var errDeviceBindUnsupported = errors.New("binding a socket to a device is not supported on this platform")

func bindSocketToDevice(fd uintptr, dev string) error {
	if dev == "" {
		return nil
	}
	return errDeviceBindUnsupported
}
