//go:build !linux

package purevpn

import (
	"errors"
	"syscall"
)

func newMarkControl(uint32) func(network, address string, rawConn syscall.RawConn) error {
	return func(_, _ string, _ syscall.RawConn) error {
		return errors.New("marking sockets is only supported on Linux")
	}
}
