//go:build linux

package purevpn

import (
	"fmt"
	"syscall"

	"golang.org/x/sys/unix"
)

// newMarkControl returns a function setting the mark given on the socket
// given, so its packets are accepted by the temporary firewall rules. It
// is meant to be used as the Control function of a [net.Dialer].
func newMarkControl(mark uint32) func(network, address string, rawConn syscall.RawConn) error {
	return func(_, _ string, rawConn syscall.RawConn) error {
		var markErr error
		err := rawConn.Control(func(fd uintptr) {
			markErr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_MARK, int(mark)) //nolint:gosec
		})
		if err != nil {
			return fmt.Errorf("controlling socket: %w", err)
		}
		if markErr != nil {
			return fmt.Errorf("setting socket mark: %w", markErr)
		}
		return nil
	}
}
