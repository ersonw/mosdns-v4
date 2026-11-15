//go:build windows

package coremain

// Windows builds keep the old behaviour: the listener itself reports a
// conflicting port. A named mutex would be the equivalent guard, but this fork
// only ships the service on Linux and macOS today.
func acquireInstanceLock(string) (func(), error) {
	return func() {}, nil
}
