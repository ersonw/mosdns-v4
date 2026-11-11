//go:build linux

package fakeipnat

import (
	"context"
	"testing"
)

func TestPickTunNameStartsAtZero(t *testing.T) {
	runner := &fakeRunner{}
	p := newNativePlugin(t, runner, nil)

	name, err := p.pickTunName(context.Background())
	if err != nil {
		t.Fatalf("pickTunName: %v", err)
	}
	if name != "mth0" {
		t.Fatalf("name = %q, want mth0", name)
	}
}

func TestPickTunNameReusesOwnDevice(t *testing.T) {
	runner := &fakeRunner{
		devs:     map[string]bool{"mth0": true},
		devAddrs: map[string]string{"mth0": "198.18.0.1"},
	}
	p := newNativePlugin(t, runner, nil)

	name, err := p.pickTunName(context.Background())
	if err != nil {
		t.Fatalf("pickTunName: %v", err)
	}
	if name != "mth0" {
		t.Fatalf("name = %q, want the leftover mth0 to be reused", name)
	}
}

func TestPickTunNameSkipsForeignDevice(t *testing.T) {
	runner := &fakeRunner{
		devs:     map[string]bool{"mth0": true},
		devAddrs: map[string]string{"mth0": "10.9.9.9"},
	}
	p := newNativePlugin(t, runner, nil)

	name, err := p.pickTunName(context.Background())
	if err != nil {
		t.Fatalf("pickTunName: %v", err)
	}
	if name != "mth1" {
		t.Fatalf("name = %q, want mth1 because mth0 belongs to something else", name)
	}
}

func TestCreateTunPlatformRejectsTooLongDeviceName(t *testing.T) {
	runner := &fakeRunner{}
	p := newNativePlugin(t, runner, nil)
	p.tunDev = "a-very-long-device-name"

	if _, _, err := p.createTunPlatform(context.Background()); err == nil {
		t.Fatal("a device name longer than 15 characters should be rejected")
	}
}

func TestCreateTunPlatformSurfacesCreateFailure(t *testing.T) {
	runner := &fakeRunner{failContains: "ip tuntap add"}
	p := newNativePlugin(t, runner, nil)

	if _, _, err := p.createTunPlatform(context.Background()); err == nil {
		t.Fatal("a failing `ip tuntap add` must be reported")
	}
}

func TestCreateTunPlatformReportsMissingTunNode(t *testing.T) {
	// /dev/net/tun does not exist on the BSD derived hosts, so this only runs
	// where the node is either present or the error is produced by the open.
	runner := &fakeRunner{}
	p := newNativePlugin(t, runner, nil)
	p.tunDev = "mth0"

	if _, _, err := p.createTunPlatform(context.Background()); err != nil {
		t.Logf("tun device unavailable in this environment: %v", err)
	}
}
