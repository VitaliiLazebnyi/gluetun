package firewall

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"sync"
	"testing"

	"github.com/qdm12/gluetun/internal/routing"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// acceptOutputMarkedImpl records AcceptOutputMarked calls, fails adding
// a rule for addFailAddr, and fails removing a rule for removeFailAddr
// removeFailures times. It fails if the context given is canceled.
type acceptOutputMarkedImpl struct {
	firewallImpl
	addFailAddr    netip.Addr
	removeFailAddr netip.Addr
	removeFailures uint

	mutex sync.Mutex
	calls []string
	rules map[string]struct{}
}

func (i *acceptOutputMarkedImpl) AcceptOutputMarked(ctx context.Context, protocol, intf string,
	ip netip.Addr, port uint16, mark uint32, remove bool,
) error {
	i.mutex.Lock()
	defer i.mutex.Unlock()
	if ctx.Err() != nil {
		return ctx.Err()
	}
	rule := fmt.Sprintf("%s %s %s:%d mark %d", intf, protocol, ip, port, mark)
	switch {
	case !remove && ip == i.addFailAddr:
		return errors.New("test add error")
	case remove && ip == i.removeFailAddr && i.removeFailures > 0:
		i.removeFailures--
		return errors.New("test remove error")
	}
	if i.rules == nil {
		i.rules = make(map[string]struct{})
	}
	if remove {
		i.calls = append(i.calls, "del "+rule)
		delete(i.rules, rule)
	} else {
		i.calls = append(i.calls, "add "+rule)
		i.rules[rule] = struct{}{}
	}
	return nil
}

func (i *acceptOutputMarkedImpl) popCalls() []string {
	i.mutex.Lock()
	defer i.mutex.Unlock()
	calls := i.calls
	i.calls = nil
	return calls
}

func (i *acceptOutputMarkedImpl) rulesCount() int {
	i.mutex.Lock()
	defer i.mutex.Unlock()
	return len(i.rules)
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
	const mark = 0x7075
	allAdded := []string{
		"add eth0 tcp 1.1.1.1:443 mark 28789",
		"add eth0 tcp 203.0.113.1:443 mark 28789",
		"add eth1 tcp 1.1.1.1:443 mark 28789",
		"add eth1 tcp 203.0.113.1:443 mark 28789",
	}
	allRemoved := []string{
		"del eth1 tcp 203.0.113.1:443 mark 28789",
		"del eth1 tcp 1.1.1.1:443 mark 28789",
		"del eth0 tcp 203.0.113.1:443 mark 28789",
		"del eth0 tcp 1.1.1.1:443 mark 28789",
	}

	testCases := map[string]struct {
		impl     *acceptOutputMarkedImpl
		disabled bool
		// betweenAddAndRevert is run after adding the rules and before reverting.
		betweenAddAndRevert func(config *Config)
		revertCtx           func() context.Context
		addCalls            []string
		addErrMessage       string
		revertCalls         []string
		revertErrMessage    string
		secondRevertCalls   []string
	}{
		"firewall_disabled": {
			impl:     &acceptOutputMarkedImpl{},
			disabled: true,
		},
		"add_and_revert": {
			impl:        &acceptOutputMarkedImpl{},
			addCalls:    allAdded,
			revertCalls: allRemoved,
		},
		"revert_with_canceled_context": {
			impl:     &acceptOutputMarkedImpl{},
			addCalls: allAdded,
			revertCtx: func() context.Context {
				ctx, cancel := context.WithCancel(context.Background())
				cancel()
				return ctx
			},
			revertCalls: allRemoved,
		},
		"revert_failure_keeps_failed_rule": {
			impl: &acceptOutputMarkedImpl{
				removeFailAddr: netip.MustParseAddr("203.0.113.1"),
				removeFailures: 1,
			},
			addCalls: allAdded,
			revertCalls: []string{
				"del eth1 tcp 1.1.1.1:443 mark 28789",
				"del eth0 tcp 203.0.113.1:443 mark 28789",
				"del eth0 tcp 1.1.1.1:443 mark 28789",
			},
			revertErrMessage: "removing rule: test remove error",
			secondRevertCalls: []string{
				"del eth1 tcp 203.0.113.1:443 mark 28789",
			},
		},
		"add_failure_reverts_added_rules": {
			impl: &acceptOutputMarkedImpl{addFailAddr: netip.MustParseAddr("203.0.113.1")},
			addCalls: []string{
				"add eth0 tcp 1.1.1.1:443 mark 28789",
				"del eth0 tcp 1.1.1.1:443 mark 28789",
			},
			addErrMessage: "adding rule: test add error",
		},
		"revert_after_disable": {
			impl:     &acceptOutputMarkedImpl{},
			addCalls: allAdded,
			betweenAddAndRevert: func(config *Config) {
				config.enabled = false
				config.disabledCount++
			},
		},
		"revert_after_disable_and_enable": {
			impl:     &acceptOutputMarkedImpl{},
			addCalls: allAdded,
			betweenAddAndRevert: func(config *Config) {
				config.disabledCount++
			},
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			config := &Config{
				impl:          testCase.impl,
				enabled:       !testCase.disabled,
				defaultRoutes: defaultRoutes,
			}

			revert, err := config.AllowOutputTemporarily(context.Background(), "tcp", mark, addrPorts)
			require.NotNil(t, revert)
			if testCase.addErrMessage != "" {
				assert.ErrorContains(t, err, testCase.addErrMessage)
			} else {
				assert.NoError(t, err)
			}
			assert.Equal(t, testCase.addCalls, testCase.impl.popCalls())

			if testCase.betweenAddAndRevert != nil {
				testCase.betweenAddAndRevert(config)
			}

			revertCtx := context.Background()
			if testCase.revertCtx != nil {
				revertCtx = testCase.revertCtx()
			}
			err = revert(revertCtx)
			if testCase.revertErrMessage != "" {
				assert.ErrorContains(t, err, testCase.revertErrMessage)
			} else {
				assert.NoError(t, err)
			}
			assert.Equal(t, testCase.revertCalls, testCase.impl.popCalls())

			err = revert(context.Background())
			assert.NoError(t, err)
			assert.Equal(t, testCase.secondRevertCalls, testCase.impl.popCalls())
		})
	}
}

func Test_Config_AllowOutputTemporarily_concurrent(t *testing.T) {
	t.Parallel()

	impl := &acceptOutputMarkedImpl{}
	config := &Config{
		impl:          impl,
		enabled:       true,
		defaultRoutes: []routing.DefaultRoute{{NetInterface: "eth0"}, {NetInterface: "eth1"}},
	}

	const workers = 10
	errs := make(chan error, workers)
	var wg sync.WaitGroup
	for i := range byte(workers) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			addrPorts := []netip.AddrPort{
				netip.AddrPortFrom(netip.AddrFrom4([4]byte{198, 51, 100, i}), 443),
				netip.AddrPortFrom(netip.AddrFrom4([4]byte{203, 0, 113, i}), 443),
			}
			revert, err := config.AllowOutputTemporarily(context.Background(), "tcp", 1, addrPorts)
			if err != nil {
				errs <- err
				return
			}
			errs <- revert(context.Background())
		}()
	}
	wg.Wait()
	close(errs)

	for err := range errs {
		assert.NoError(t, err)
	}
	assert.Zero(t, impl.rulesCount(), "all rules must be removed")
	calls := impl.popCalls()
	assert.Len(t, calls, workers*2*2*2) // add and remove, 2 addresses, 2 interfaces
	adds := slices.DeleteFunc(slices.Clone(calls), func(call string) bool { return call[:3] != "add" })
	assert.Len(t, adds, workers*2*2)
}
