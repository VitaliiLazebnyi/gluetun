package firewall

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"slices"
	"strings"
	"time"
	"unicode"
)

// AllowOutputTemporarily allows output traffic of the given protocol
// to each of the given addresses through the default route interfaces,
// only for packets marked with the given mark (see SO_MARK), for example
// to reach a VPN provider API before the VPN is up. Other programs sharing
// the network namespace cannot use these rules, unless they can mark their
// packets with the same mark, which requires the CAP_NET_ADMIN capability,
// or CAP_NET_RAW since Linux 5.17, and knowing the mark value. If supported,
// the rules also only match packets from sockets of processes in the cgroup
// of this program, so programs in other containers sharing the network
// namespace cannot use these rules, even if they guess the mark value.
// IPv6 addresses are skipped. The revert function returned is never nil,
// even if an error is returned, and must be called to remove the rules
// added. On error, the rules added are already removed, except for the
// ones failing to be removed. The revert function removes the rules even if
// its context is canceled, and returns an error for the rules it failed to
// remove, which are kept to be removed by calling the revert function again.
// It is a no-op if the firewall is disabled, or was disabled since the rules
// were added, since disabling the firewall removes all the rules added.
func (c *Config) AllowOutputTemporarily(ctx context.Context,
	protocol string, mark uint32, addrPorts []netip.AddrPort,
) (revert func(ctx context.Context) error, err error) {
	c.stateMutex.Lock()
	defer c.stateMutex.Unlock()

	noop := func(context.Context) error { return nil }
	if !c.enabled {
		return noop, nil
	}

	if c.cgroupPath == "" && !c.cgroupMatchWarned {
		c.cgroupMatchWarned = true
		c.logger.Warn("cgroup v2 path not found, temporary firewall rules only match the socket mark")
	}

	added := make([]markedRule, 0, len(addrPorts)*len(c.defaultRoutes))
	disabledCount := c.disabledCount

	// removeAdded must be called with the state mutex locked.
	removeAdded := func(ctx context.Context) error {
		if !c.enabled || c.disabledCount != disabledCount {
			added = nil // rules already removed by disabling the firewall
			return nil
		}
		var errs []error
		var failed []markedRule
		for _, rule := range slices.Backward(added) {
			err := c.removeOutputMarked(ctx, protocol, mark, rule)
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
			rule := markedRule{intf: defaultRoute.NetInterface, addrPort: addrPort, cgroupPath: c.cgroupPath}
			possiblyAdded, err := c.addOutputMarkedWithFallback(ctx, protocol, mark, rule)
			// The rules are recorded even on error, since they may have been added,
			// for example before the context got canceled. Removing a rule
			// which does not exist succeeds.
			added = append(added, possiblyAdded...)
			if err != nil {
				err = fmt.Errorf("adding rule: %w", err)
				revertErr := removeAdded(ctx)
				if revertErr != nil {
					err = fmt.Errorf("%w (reverting: %w)", err, revertErr)
				}
				// revert is returned to remove rules failing to be removed above.
				return revert, err
			}
		}
	}

	return revert, nil
}

type markedRule struct {
	intf     string
	addrPort netip.AddrPort
	// cgroupPath is the cgroup path matched, or "" for no cgroup match.
	cgroupPath string
}

// addOutputMarkedWithFallback adds the rule given, falling back on the
// rule without cgroup match if adding the rule with the cgroup match fails,
// in which case the cgroup match is no longer used for next rules. It returns
// the rules which may have been added, even on error, for example if the
// context got canceled after a rule got added. It must be called with the
// state mutex locked.
func (c *Config) addOutputMarkedWithFallback(ctx context.Context, protocol string, mark uint32,
	rule markedRule,
) (possiblyAdded []markedRule, err error) {
	const maxRules = 2 // with and without cgroup match
	possiblyAdded = make([]markedRule, 1, maxRules)
	possiblyAdded[0] = rule
	err = c.addOutputMarked(ctx, protocol, mark, rule)
	if err == nil || rule.cgroupPath == "" {
		return possiblyAdded, err
	}

	cgroupErr := err
	rule.cgroupPath = ""
	possiblyAdded = append(possiblyAdded, rule)
	err = c.addOutputMarked(ctx, protocol, mark, rule)
	if err != nil {
		return possiblyAdded, err
	}
	c.cgroupPath = "" // do not try the cgroup match again
	c.cgroupMatchWarned = true
	c.logger.Warn("cgroup match is not supported, temporary firewall rules " +
		"only match the socket mark: " + cgroupErr.Error())
	return possiblyAdded, nil
}

func (c *Config) addOutputMarked(ctx context.Context, protocol string, mark uint32,
	rule markedRule,
) error {
	const remove = false
	return c.impl.AcceptOutputMarked(ctx, protocol, rule.intf, rule.addrPort.Addr(),
		rule.addrPort.Port(), rule.cgroupPath, mark, remove)
}

// removeOutputMarked removes the rule given, even if the context given
// is canceled, for example on shutdown, to not leave the firewall open.
// Removing a rule which does not exist succeeds.
func (c *Config) removeOutputMarked(ctx context.Context, protocol string, mark uint32,
	rule markedRule,
) error {
	const ruleTimeout = 5 * time.Second
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), ruleTimeout)
	defer cancel()
	const remove = true
	return c.impl.AcceptOutputMarked(ctx, protocol, rule.intf, rule.addrPort.Addr(),
		rule.addrPort.Port(), rule.cgroupPath, mark, remove)
}

// readCgroupPath returns the cgroup v2 path of this program from the
// /proc/self/cgroup file given, relative to the cgroup namespace of the
// program, which is usually "/" in a container. It returns the empty string
// if the path cannot be found, for example with cgroup v1 only, or if it
// contains a space, which cannot be matched in the iptables rules listed.
func readCgroupPath(procCgroupPath string) (path string) {
	data, err := os.ReadFile(procCgroupPath)
	if err != nil {
		return ""
	}
	for line := range strings.Lines(string(data)) {
		path, ok := strings.CutPrefix(strings.TrimSuffix(line, "\n"), "0::")
		switch {
		case !ok:
			continue
		case !strings.HasPrefix(path, "/") || strings.ContainsFunc(path, unicode.IsSpace):
			return ""
		}
		return path
	}
	return ""
}
