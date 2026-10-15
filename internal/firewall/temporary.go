package firewall

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"time"
)

// AllowOutputTemporarily allows output traffic of the given protocol
// to each of the given addresses through the default route interfaces,
// only for packets marked with the given mark (see SO_MARK), for example
// to reach a VPN provider API before the VPN is up. Other programs sharing
// the network namespace cannot use these rules, unless they can mark their
// packets with the same mark, which requires the CAP_NET_ADMIN capability,
// or CAP_NET_RAW since Linux 5.17, and knowing the mark value.
// IPv6 addresses are skipped. The revert function returned is never nil,
// even if an error is returned, and must be called to remove the rules
// added. On error, the rules added are already removed, except for the
// ones failing to be removed. The revert function removes the rules even if its
// context is canceled, and returns an error for the rules it failed to
// remove, which are kept to be removed by a next call. It is a no-op if
// the firewall is disabled, or was disabled since the rules were added,
// since disabling the firewall removes all the rules added.
func (c *Config) AllowOutputTemporarily(ctx context.Context,
	protocol string, mark uint32, addrPorts []netip.AddrPort,
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
	disabledCount := c.disabledCount

	// removeAdded must be called with the state mutex locked.
	removeAdded := func(ctx context.Context) error {
		if !c.enabled || c.disabledCount != disabledCount {
			added = nil // rules already removed by disabling the firewall
			return nil
		}
		// Rules must be removed even if the context is canceled, for
		// example on shutdown, to not leave the firewall open.
		ctx = context.WithoutCancel(ctx)
		var errs []error
		var failed []rule
		for _, rule := range slices.Backward(added) {
			const ruleTimeout = 5 * time.Second
			ruleCtx, cancel := context.WithTimeout(ctx, ruleTimeout)
			const remove = true
			err := c.impl.AcceptOutputMarked(ruleCtx, protocol, rule.intf,
				rule.addrPort.Addr(), rule.addrPort.Port(), mark, remove)
			cancel()
			if err != nil {
				errs = append(errs, fmt.Errorf("removing rule: %w", err))
				failed = append(failed, rule)
			}
		}
		slices.Reverse(failed)
		added = failed
		return errors.Join(errs...)
	}

	revert = func(ctx context.Context) error {
		c.stateMutex.Lock()
		defer c.stateMutex.Unlock()
		return removeAdded(ctx)
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
			err = c.impl.AcceptOutputMarked(ctx, protocol, defaultRoute.NetInterface,
				addrPort.Addr(), addrPort.Port(), mark, remove)
			if err != nil {
				err = fmt.Errorf("adding rule: %w", err)
				revertErr := removeAdded(ctx)
				if revertErr != nil {
					err = fmt.Errorf("%w (reverting: %w)", err, revertErr)
				}
				// revert is returned to remove rules failing to be removed above.
				return revert, err
			}
			added = append(added, rule{intf: defaultRoute.NetInterface, addrPort: addrPort})
		}
	}

	return revert, nil
}
