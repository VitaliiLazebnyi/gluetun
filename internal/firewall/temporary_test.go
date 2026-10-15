package firewall

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"testing"

	"github.com/qdm12/gluetun/internal/routing"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// acceptOutputImpl records AcceptOutput calls and fails on failAddr.
type acceptOutputImpl struct {
	firewallImpl
	failAddr netip.Addr
	calls    []string
}

func (i *acceptOutputImpl) AcceptOutput(_ context.Context, protocol, intf string,
	ip netip.Addr, port uint16, remove bool,
) error {
	if ip == i.failAddr && !remove {
		return errors.New("test error")
	}
	i.calls = append(i.calls, fmt.Sprintf("%s %s %s %s:%d", map[bool]string{false: "add", true: "del"}[remove],
		intf, protocol, ip, port))
	return nil
}

func Test_Config_AllowOutputTemporarily(t *testing.T) {
	t.Parallel()

	addrPorts := []netip.AddrPort{
		netip.MustParseAddrPort("1.1.1.1:443"),
		netip.MustParseAddrPort("[2606:4700::1111]:443"), // skipped
		netip.MustParseAddrPort("203.0.113.1:443"),
	}
	defaultRoutes := []routing.DefaultRoute{
		{NetInterface: "eth0"}, {NetInterface: "eth0"}, {NetInterface: "eth1"},
	}

	t.Run("disabled", func(t *testing.T) {
		t.Parallel()
		impl := &acceptOutputImpl{}
		c := &Config{impl: impl, defaultRoutes: defaultRoutes}
		revert, err := c.AllowOutputTemporarily(context.Background(), "tcp", addrPorts)
		require.NoError(t, err)
		require.NoError(t, revert(context.Background()))
		assert.Empty(t, impl.calls)
	})

	t.Run("add_and_revert", func(t *testing.T) {
		t.Parallel()
		impl := &acceptOutputImpl{}
		c := &Config{impl: impl, enabled: true, defaultRoutes: defaultRoutes}
		revert, err := c.AllowOutputTemporarily(context.Background(), "tcp", addrPorts)
		require.NoError(t, err)
		assert.Equal(t, []string{
			"add eth0 tcp 1.1.1.1:443",
			"add eth0 tcp 203.0.113.1:443",
			"add eth1 tcp 1.1.1.1:443",
			"add eth1 tcp 203.0.113.1:443",
		}, impl.calls)

		impl.calls = nil
		require.NoError(t, revert(context.Background()))
		assert.Equal(t, []string{
			"del eth0 tcp 1.1.1.1:443",
			"del eth0 tcp 203.0.113.1:443",
			"del eth1 tcp 1.1.1.1:443",
			"del eth1 tcp 203.0.113.1:443",
		}, impl.calls)

		impl.calls = nil
		require.NoError(t, revert(context.Background()))
		assert.Empty(t, impl.calls, "second revert must be a no-op")
	})

	t.Run("failure_reverts_added_rules", func(t *testing.T) {
		t.Parallel()
		impl := &acceptOutputImpl{failAddr: netip.MustParseAddr("203.0.113.1")}
		c := &Config{impl: impl, enabled: true, defaultRoutes: defaultRoutes}
		_, err := c.AllowOutputTemporarily(context.Background(), "tcp", addrPorts)
		require.ErrorContains(t, err, "allowing output to tcp 203.0.113.1:443: test error")
		assert.Equal(t, []string{
			"add eth0 tcp 1.1.1.1:443",
			"del eth0 tcp 1.1.1.1:443",
		}, impl.calls)
	})
}
