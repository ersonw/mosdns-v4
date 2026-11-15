//go:build !linux

package alias

import "net"

// bindToDevice is a no-op outside linux: SO_BINDTODEVICE does not exist there,
// and the plugin does not build a tun data path on those platforms anyway.
func bindToDevice(_ *net.Dialer, _ string) {}
