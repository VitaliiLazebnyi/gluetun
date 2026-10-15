//go:build linux

package purevpn

import (
	"context"
	"errors"
	"net"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

func Test_newMarkControl(t *testing.T) {
	t.Parallel()

	listener, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = listener.Close() })

	const mark = 0x7075
	dialer := &net.Dialer{Control: newMarkControl(mark)}
	conn, err := dialer.DialContext(context.Background(), "tcp", listener.Addr().String())
	if errors.Is(err, unix.EPERM) {
		assert.ErrorContains(t, err, "setting socket mark: operation not permitted")
		t.Skip("setting a socket mark requires the CAP_NET_ADMIN or CAP_NET_RAW capability")
	}
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })

	tcpConn, ok := conn.(*net.TCPConn)
	require.True(t, ok)
	rawConn, err := tcpConn.SyscallConn()
	require.NoError(t, err)
	var socketMark int
	var getErr error
	err = rawConn.Control(func(fd uintptr) {
		socketMark, getErr = unix.GetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_MARK) //nolint:gosec
	})
	require.NoError(t, err)
	require.NoError(t, getErr)
	assert.Equal(t, mark, socketMark)
}

func Test_newMarkControl_closedSocket(t *testing.T) {
	t.Parallel()

	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	require.NoError(t, err)
	rawConn, err := conn.SyscallConn()
	require.NoError(t, err)
	require.NoError(t, conn.Close())

	err = newMarkControl(0x7075)("udp", "127.0.0.1:1", rawConn)

	assert.ErrorContains(t, err, "controlling socket: ")
}

func Test_newMarkControl_notSocket(t *testing.T) {
	t.Parallel()

	reader, writer, err := os.Pipe()
	require.NoError(t, err)
	t.Cleanup(func() {
		_ = reader.Close()
		_ = writer.Close()
	})
	rawConn, err := reader.SyscallConn()
	require.NoError(t, err)

	err = newMarkControl(0x7075)("tcp", "127.0.0.1:443", rawConn)

	assert.EqualError(t, err, "setting socket mark: socket operation on non-socket")
}
