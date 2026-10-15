//go:build !linux

package purevpn

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_newMarkControl(t *testing.T) {
	t.Parallel()

	err := newMarkControl(0x7075)("tcp", "127.0.0.1:443", nil)

	assert.EqualError(t, err, "marking sockets is only supported on Linux")
}
