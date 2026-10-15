package firewall

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
)

// AllowOutputTemporarily allows output traffic of the given protocol
// to each of the given addresses through the default route interfaces,
// for example to reach a VPN provider API before the VPN is up.
// IPv6 addresses are skipped. The revert function returned must be
// called to remove the rules added, and is a no-op if the firewall
// is disabled.
func (c *Config) AllowOutputTemporarily(ctx context.Context,
	protocol string, addrPorts []netip.AddrPort,
) (revert func(ctx context.Context) error, err error) {
	c.stateMutex.Lock()
	defer c.stateMutex.Unlock()

	noop := func(context.Context) error { return nil }
	if !c.enabled {
		return noop, nil
	}

	type rule struct {
		intf     string
		addrPort netip.AddrPort
	}
	added := make([]rule, 0, len(addrPorts)*len(c.defaultRoutes))
	revert = func(ctx context.Context) error {
		c.stateMutex.Lock()
		defer c.stateMutex.Unlock()
		var errs []error
		const remove = true
		for _, rule := range added {
			err := c.impl.AcceptOutput(ctx, protocol, rule.intf,
				rule.addrPort.Addr(), rule.addrPort.Port(), remove)
			if err != nil {
				errs = append(errs, fmt.Errorf("removing rule for %s: %w", rule.addrPort, err))
			}
		}
		added = nil
		return errors.Join(errs...)
	}

	interfacesSeen := make(map[string]struct{}, len(c.defaultRoutes))
	for _, defaultRoute := range c.defaultRoutes {
		_, seen := interfacesSeen[defaultRoute.NetInterface]
		if seen {
			continue
		}
		interfacesSeen[defaultRoute.NetInterface] = struct{}{}

		for _, addrPort := range addrPorts {
			if !addrPort.Addr().Is4() {
				continue
			}
			const remove = false
			err = c.impl.AcceptOutput(ctx, protocol, defaultRoute.NetInterface,
				addrPort.Addr(), addrPort.Port(), remove)
			if err != nil {
				c.stateMutex.Unlock()
				revertErr := revert(ctx)
				c.stateMutex.Lock()
				if revertErr != nil {
					err = fmt.Errorf("%w (reverting: %w)", err, revertErr)
				}
				return noop, fmt.Errorf("allowing output to %s %s: %w", protocol, addrPort, err)
			}
			added = append(added, rule{intf: defaultRoute.NetInterface, addrPort: addrPort})
		}
	}

	return revert, nil
}
