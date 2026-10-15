package firewall

import (
	"context"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/qdm12/gluetun/internal/routing"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
)

// removalContextMatcher matches a context which is not canceled and
// has a deadline of at most 5 seconds, as used to remove a rule even
// if the context of the caller is canceled.
type removalContextMatcher struct{}

func (removalContextMatcher) Matches(x any) bool {
	ctx, ok := x.(context.Context)
	if !ok || ctx.Err() != nil {
		return false
	}
	deadline, ok := ctx.Deadline()
	return ok && time.Until(deadline) <= 5*time.Second
}

func (removalContextMatcher) String() string {
	return "is a non canceled context with a deadline of at most 5 seconds"
}

func Test_removalContextMatcher(t *testing.T) {
	t.Parallel()

	canceledCtx, cancel := context.WithTimeout(context.Background(), time.Second)
	cancel()
	longCtx, longCancel := context.WithTimeout(context.Background(), time.Hour)
	t.Cleanup(longCancel)
	shortCtx, shortCancel := context.WithTimeout(context.Background(), time.Second)
	t.Cleanup(shortCancel)

	matcher := removalContextMatcher{}
	assert.False(t, matcher.Matches("not a context"))
	assert.False(t, matcher.Matches(canceledCtx))
	assert.False(t, matcher.Matches(context.Background()))
	assert.False(t, matcher.Matches(longCtx))
	assert.True(t, matcher.Matches(shortCtx))
	assert.Equal(t, "is a non canceled context with a deadline of at most 5 seconds", matcher.String())
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
	ip1 := netip.MustParseAddr("1.1.1.1")
	ip2 := netip.MustParseAddr("203.0.113.1")
	const mark = 0x7075
	const add, remove = false, true
	errTest := errors.New("test error")
	removal := removalContextMatcher{}

	type testContext struct {
		ctx    context.Context
		cancel context.CancelFunc
	}

	testCases := map[string]struct {
		disabled   bool
		cgroupPath string
		// makeImpl sets the calls expected when adding the rules,
		// and returns the calls expected when reverting the rules
		// the first time and the second time.
		makeImpl func(impl *MockfirewallImpl, test testContext) (
			firstRevert, secondRevert func())
		makeLogger func(logger *MockLogger)
		// betweenAddAndRevert is run after adding the rules and before reverting.
		betweenAddAndRevert func(config *Config)
		cancelBeforeRevert  bool
		addErrMessage       string
		revertErrMessage    string
		cgroupPathAfter     string
	}{
		"firewall_disabled": {
			disabled: true,
			makeImpl: func(*MockfirewallImpl, testContext) (func(), func()) {
				return func() {}, func() {}
			},
		},
		"add_and_revert": {
			cgroupPath: "/",
			makeImpl: func(impl *MockfirewallImpl, test testContext) (func(), func()) {
				gomock.InOrder(
					impl.EXPECT().AcceptOutputMarked(test.ctx, "tcp", "eth0", ip1, uint16(443), "/", uint32(mark), add).Return(nil),
					impl.EXPECT().AcceptOutputMarked(test.ctx, "tcp", "eth0", ip2, uint16(443), "/", uint32(mark), add).Return(nil),
					impl.EXPECT().AcceptOutputMarked(test.ctx, "tcp", "eth1", ip1, uint16(443), "/", uint32(mark), add).Return(nil),
					impl.EXPECT().AcceptOutputMarked(test.ctx, "tcp", "eth1", ip2, uint16(443), "/", uint32(mark), add).Return(nil),
				)
				firstRevert := func() {
					gomock.InOrder(
						impl.EXPECT().AcceptOutputMarked(removal, "tcp", "eth1", ip2, uint16(443), "/", uint32(mark), remove).Return(nil),
						impl.EXPECT().AcceptOutputMarked(removal, "tcp", "eth1", ip1, uint16(443), "/", uint32(mark), remove).Return(nil),
						impl.EXPECT().AcceptOutputMarked(removal, "tcp", "eth0", ip2, uint16(443), "/", uint32(mark), remove).Return(nil),
						impl.EXPECT().AcceptOutputMarked(removal, "tcp", "eth0", ip1, uint16(443), "/", uint32(mark), remove).Return(nil),
					)
				}
				return firstRevert, func() {}
			},
			cgroupPathAfter: "/",
		},
		"revert_with_canceled_context": {
			cgroupPath: "/",
			makeImpl: func(impl *MockfirewallImpl, test testContext) (func(), func()) {
				impl.EXPECT().AcceptOutputMarked(test.ctx, "tcp", "eth0", ip1, uint16(443), "/", uint32(mark), add).Return(nil)
				impl.EXPECT().AcceptOutputMarked(test.ctx, "tcp", "eth1", ip1, uint16(443), "/", uint32(mark), add).Return(nil)
				impl.EXPECT().AcceptOutputMarked(test.ctx, "tcp", "eth0", ip2, uint16(443), "/", uint32(mark), add).Return(nil)
				impl.EXPECT().AcceptOutputMarked(test.ctx, "tcp", "eth1", ip2, uint16(443), "/", uint32(mark), add).Return(nil)
				firstRevert := func() {
					impl.EXPECT().AcceptOutputMarked(removal, "tcp", "eth0", ip1, uint16(443), "/", uint32(mark), remove).Return(nil)
					impl.EXPECT().AcceptOutputMarked(removal, "tcp", "eth1", ip1, uint16(443), "/", uint32(mark), remove).Return(nil)
					impl.EXPECT().AcceptOutputMarked(removal, "tcp", "eth0", ip2, uint16(443), "/", uint32(mark), remove).Return(nil)
					impl.EXPECT().AcceptOutputMarked(removal, "tcp", "eth1", ip2, uint16(443), "/", uint32(mark), remove).Return(nil)
				}
				return firstRevert, func() {}
			},
			cancelBeforeRevert: true,
			cgroupPathAfter:    "/",
		},
		"revert_failure_keeps_failed_rule": {
			cgroupPath: "/",
			makeImpl: func(impl *MockfirewallImpl, test testContext) (func(), func()) {
				impl.EXPECT().AcceptOutputMarked(test.ctx, "tcp", "eth0", ip1, uint16(443), "/", uint32(mark), add).Return(nil)
				impl.EXPECT().AcceptOutputMarked(test.ctx, "tcp", "eth1", ip1, uint16(443), "/", uint32(mark), add).Return(nil)
				impl.EXPECT().AcceptOutputMarked(test.ctx, "tcp", "eth0", ip2, uint16(443), "/", uint32(mark), add).Return(nil)
				impl.EXPECT().AcceptOutputMarked(test.ctx, "tcp", "eth1", ip2, uint16(443), "/", uint32(mark), add).Return(nil)
				firstRevert := func() {
					impl.EXPECT().AcceptOutputMarked(removal, "tcp", "eth0", ip1, uint16(443), "/", uint32(mark), remove).Return(nil)
					impl.EXPECT().AcceptOutputMarked(removal, "tcp", "eth1", ip1, uint16(443), "/", uint32(mark), remove).Return(nil)
					impl.EXPECT().AcceptOutputMarked(removal, "tcp", "eth0", ip2, uint16(443), "/", uint32(mark), remove).Return(nil)
					impl.EXPECT().AcceptOutputMarked(removal, "tcp", "eth1", ip2, uint16(443), "/", uint32(mark), remove).
						Return(errTest)
				}
				secondRevert := func() {
					impl.EXPECT().AcceptOutputMarked(removal, "tcp", "eth1", ip2, uint16(443), "/", uint32(mark), remove).Return(nil)
				}
				return firstRevert, secondRevert
			},
			revertErrMessage: "removing rule: test error",
			cgroupPathAfter:  "/",
		},
		"add_failure_with_canceled_context_removes_rules": {
			makeImpl: func(impl *MockfirewallImpl, test testContext) (func(), func()) {
				gomock.InOrder(
					impl.EXPECT().AcceptOutputMarked(test.ctx, "tcp", "eth0", ip1, uint16(443), "", uint32(mark), add).Return(nil),
					impl.EXPECT().AcceptOutputMarked(test.ctx, "tcp", "eth0", ip2, uint16(443), "", uint32(mark), add).
						DoAndReturn(func(context.Context, string, string, netip.Addr, uint16, string, uint32, bool) error {
							// The rule may be added before the context is canceled.
							test.cancel()
							return context.Canceled
						}),
					impl.EXPECT().AcceptOutputMarked(removal, "tcp", "eth0", ip2, uint16(443), "", uint32(mark), remove).Return(nil),
					impl.EXPECT().AcceptOutputMarked(removal, "tcp", "eth0", ip1, uint16(443), "", uint32(mark), remove).Return(nil),
				)
				return func() {}, func() {}
			},
			makeLogger: func(logger *MockLogger) {
				logger.EXPECT().Warn("cgroup v2 path not found, temporary firewall rules only match the socket mark")
			},
			addErrMessage: "adding rule: context canceled",
		},
		"add_failure_with_failed_removal": {
			makeImpl: func(impl *MockfirewallImpl, test testContext) (func(), func()) {
				gomock.InOrder(
					impl.EXPECT().AcceptOutputMarked(test.ctx, "tcp", "eth0", ip1, uint16(443), "", uint32(mark), add).Return(errTest),
					impl.EXPECT().AcceptOutputMarked(removal, "tcp", "eth0", ip1, uint16(443), "", uint32(mark), remove).
						Return(errors.New("test remove error")),
				)
				retryRevert := func() {
					impl.EXPECT().AcceptOutputMarked(removal, "tcp", "eth0", ip1, uint16(443), "", uint32(mark), remove).Return(nil)
				}
				return retryRevert, func() {}
			},
			makeLogger: func(logger *MockLogger) {
				logger.EXPECT().Warn("cgroup v2 path not found, temporary firewall rules only match the socket mark")
			},
			addErrMessage: "adding rule: test error (reverting: removing rule: test remove error)",
		},
		"cgroup_match_unsupported": {
			cgroupPath: "/",
			makeImpl: func(impl *MockfirewallImpl, test testContext) (func(), func()) {
				gomock.InOrder(
					impl.EXPECT().AcceptOutputMarked(test.ctx, "tcp", "eth0", ip1, uint16(443), "/", uint32(mark), add).
						Return(errors.New("no xt_cgroup")),
					impl.EXPECT().AcceptOutputMarked(test.ctx, "tcp", "eth0", ip1, uint16(443), "", uint32(mark), add).Return(nil),
					impl.EXPECT().AcceptOutputMarked(test.ctx, "tcp", "eth0", ip2, uint16(443), "", uint32(mark), add).Return(nil),
					impl.EXPECT().AcceptOutputMarked(test.ctx, "tcp", "eth1", ip1, uint16(443), "", uint32(mark), add).Return(nil),
					impl.EXPECT().AcceptOutputMarked(test.ctx, "tcp", "eth1", ip2, uint16(443), "", uint32(mark), add).Return(nil),
				)
				firstRevert := func() {
					gomock.InOrder(
						impl.EXPECT().AcceptOutputMarked(removal, "tcp", "eth1", ip2, uint16(443), "", uint32(mark), remove).Return(nil),
						impl.EXPECT().AcceptOutputMarked(removal, "tcp", "eth1", ip1, uint16(443), "", uint32(mark), remove).Return(nil),
						impl.EXPECT().AcceptOutputMarked(removal, "tcp", "eth0", ip2, uint16(443), "", uint32(mark), remove).Return(nil),
						impl.EXPECT().AcceptOutputMarked(removal, "tcp", "eth0", ip1, uint16(443), "", uint32(mark), remove).Return(nil),
						// The rule with the cgroup match may have been added.
						impl.EXPECT().AcceptOutputMarked(removal, "tcp", "eth0", ip1, uint16(443), "/", uint32(mark), remove).Return(nil),
					)
				}
				return firstRevert, func() {}
			},
			makeLogger: func(logger *MockLogger) {
				logger.EXPECT().Warn("cgroup match is not supported, temporary firewall rules only match " +
					"the socket mark: no xt_cgroup")
			},
		},
		"cgroup_match_and_fallback_fail": {
			cgroupPath: "/",
			makeImpl: func(impl *MockfirewallImpl, test testContext) (func(), func()) {
				gomock.InOrder(
					impl.EXPECT().AcceptOutputMarked(test.ctx, "tcp", "eth0", ip1, uint16(443), "/", uint32(mark), add).
						Return(errors.New("first error")),
					impl.EXPECT().AcceptOutputMarked(test.ctx, "tcp", "eth0", ip1, uint16(443), "", uint32(mark), add).Return(errTest),
					impl.EXPECT().AcceptOutputMarked(removal, "tcp", "eth0", ip1, uint16(443), "", uint32(mark), remove).Return(nil),
					impl.EXPECT().AcceptOutputMarked(removal, "tcp", "eth0", ip1, uint16(443), "/", uint32(mark), remove).Return(nil),
				)
				return func() {}, func() {}
			},
			addErrMessage:   "adding rule: test error",
			cgroupPathAfter: "/",
		},
		"revert_after_disable": {
			cgroupPath: "/",
			makeImpl: func(impl *MockfirewallImpl, test testContext) (func(), func()) {
				impl.EXPECT().AcceptOutputMarked(test.ctx, "tcp", "eth0", ip1, uint16(443), "/", uint32(mark), add).Return(nil)
				impl.EXPECT().AcceptOutputMarked(test.ctx, "tcp", "eth1", ip1, uint16(443), "/", uint32(mark), add).Return(nil)
				impl.EXPECT().AcceptOutputMarked(test.ctx, "tcp", "eth0", ip2, uint16(443), "/", uint32(mark), add).Return(nil)
				impl.EXPECT().AcceptOutputMarked(test.ctx, "tcp", "eth1", ip2, uint16(443), "/", uint32(mark), add).Return(nil)
				return func() {}, func() {}
			},
			betweenAddAndRevert: func(config *Config) {
				config.enabled = false
				config.disabledCount++
			},
			cgroupPathAfter: "/",
		},
		"revert_after_disable_and_enable": {
			cgroupPath: "/",
			makeImpl: func(impl *MockfirewallImpl, test testContext) (func(), func()) {
				impl.EXPECT().AcceptOutputMarked(test.ctx, "tcp", "eth0", ip1, uint16(443), "/", uint32(mark), add).Return(nil)
				impl.EXPECT().AcceptOutputMarked(test.ctx, "tcp", "eth1", ip1, uint16(443), "/", uint32(mark), add).Return(nil)
				impl.EXPECT().AcceptOutputMarked(test.ctx, "tcp", "eth0", ip2, uint16(443), "/", uint32(mark), add).Return(nil)
				impl.EXPECT().AcceptOutputMarked(test.ctx, "tcp", "eth1", ip2, uint16(443), "/", uint32(mark), add).Return(nil)
				return func() {}, func() {}
			},
			betweenAddAndRevert: func(config *Config) {
				config.disabledCount++
			},
			cgroupPathAfter: "/",
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			ctrl := gomock.NewController(t)

			ctx, cancel := context.WithCancel(context.Background())
			t.Cleanup(cancel)
			impl := NewMockfirewallImpl(ctrl)
			firstRevert, secondRevert := testCase.makeImpl(impl, testContext{ctx: ctx, cancel: cancel})
			logger := NewMockLogger(ctrl)
			if testCase.makeLogger != nil {
				testCase.makeLogger(logger)
			}
			config := &Config{
				impl:          impl,
				logger:        logger,
				enabled:       !testCase.disabled,
				defaultRoutes: defaultRoutes,
				cgroupPath:    testCase.cgroupPath,
			}

			revert, err := config.AllowOutputTemporarily(ctx, "tcp", mark, addrPorts)
			require.NotNil(t, revert)
			if testCase.addErrMessage != "" {
				assert.ErrorContains(t, err, testCase.addErrMessage)
			} else {
				assert.NoError(t, err)
			}
			assert.Equal(t, testCase.cgroupPathAfter, config.cgroupPath)

			if testCase.betweenAddAndRevert != nil {
				testCase.betweenAddAndRevert(config)
			}

			if testCase.cancelBeforeRevert {
				cancel()
			}
			firstRevert()
			err = revert(ctx)
			if testCase.revertErrMessage != "" {
				assert.ErrorContains(t, err, testCase.revertErrMessage)
			} else {
				assert.NoError(t, err)
			}

			secondRevert()
			err = revert(context.Background())
			assert.NoError(t, err)
		})
	}
}

func Test_Config_AllowOutputTemporarily_warnsOnce(t *testing.T) {
	t.Parallel()

	testCases := map[string]struct {
		cgroupPath string
		makeImpl   func(impl *MockfirewallImpl, ctx context.Context)
		warning    string
	}{
		"cgroup_path_not_found": {
			makeImpl: func(impl *MockfirewallImpl, ctx context.Context) {
				impl.EXPECT().AcceptOutputMarked(ctx, "tcp", "eth0", netip.MustParseAddr("1.1.1.1"),
					uint16(443), "", uint32(1), false).Return(nil).Times(2)
			},
			warning: "cgroup v2 path not found, temporary firewall rules only match the socket mark",
		},
		"cgroup_match_unsupported": {
			cgroupPath: "/system.slice/docker-1.scope",
			makeImpl: func(impl *MockfirewallImpl, ctx context.Context) {
				impl.EXPECT().AcceptOutputMarked(ctx, "tcp", "eth0", netip.MustParseAddr("1.1.1.1"),
					uint16(443), "/system.slice/docker-1.scope", uint32(1), false).Return(errors.New("test error"))
				impl.EXPECT().AcceptOutputMarked(ctx, "tcp", "eth0", netip.MustParseAddr("1.1.1.1"),
					uint16(443), "", uint32(1), false).Return(nil).Times(2)
			},
			warning: "cgroup match is not supported, temporary firewall rules only match the socket mark: test error",
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			ctrl := gomock.NewController(t)

			ctx := context.Background()
			impl := NewMockfirewallImpl(ctrl)
			testCase.makeImpl(impl, ctx)
			logger := NewMockLogger(ctrl)
			logger.EXPECT().Warn(testCase.warning)
			config := &Config{
				impl:          impl,
				logger:        logger,
				enabled:       true,
				defaultRoutes: []routing.DefaultRoute{{NetInterface: "eth0"}},
				cgroupPath:    testCase.cgroupPath,
			}

			addrPorts := []netip.AddrPort{netip.MustParseAddrPort("1.1.1.1:443")}
			for range 2 {
				_, err := config.AllowOutputTemporarily(ctx, "tcp", 1, addrPorts)
				require.NoError(t, err)
			}
		})
	}
}

func Test_Config_AllowOutputTemporarily_concurrent(t *testing.T) {
	t.Parallel()
	ctrl := gomock.NewController(t)

	ctx := context.Background()
	const workers = 10
	interfaces := [...]string{"eth0", "eth1"}
	impl := NewMockfirewallImpl(ctrl)
	addrPortsPerWorker := make([][]netip.AddrPort, workers)
	for i := range byte(workers) {
		addrPortsPerWorker[i] = []netip.AddrPort{
			netip.AddrPortFrom(netip.AddrFrom4([4]byte{198, 51, 100, i}), 443),
			netip.AddrPortFrom(netip.AddrFrom4([4]byte{203, 0, 113, i}), 443),
		}
		for _, intf := range interfaces {
			for _, addrPort := range addrPortsPerWorker[i] {
				impl.EXPECT().AcceptOutputMarked(ctx, "tcp", intf, addrPort.Addr(),
					uint16(443), "/", uint32(1), false).Return(nil)
				impl.EXPECT().AcceptOutputMarked(removalContextMatcher{}, "tcp", intf, addrPort.Addr(),
					uint16(443), "/", uint32(1), true).Return(nil)
			}
		}
	}
	config := &Config{
		impl:          impl,
		enabled:       true,
		defaultRoutes: []routing.DefaultRoute{{NetInterface: interfaces[0]}, {NetInterface: interfaces[1]}},
		cgroupPath:    "/",
	}

	errs := make(chan error, workers)
	var wg sync.WaitGroup
	for _, addrPorts := range addrPortsPerWorker {
		wg.Go(func() {
			revert, err := config.AllowOutputTemporarily(ctx, "tcp", 1, addrPorts)
			if err != nil {
				errs <- err
				return
			}
			errs <- revert(context.Background())
		})
	}
	wg.Wait()
	close(errs)

	for err := range errs {
		assert.NoError(t, err)
	}
}

func Test_readCgroupPath(t *testing.T) {
	t.Parallel()

	testCases := map[string]struct {
		content *string
		path    string
	}{
		"no_file": {},
		"cgroup_namespace_root": {
			content: new("0::/\n"),
			path:    "/",
		},
		"hybrid_cgroup_host_namespace": {
			content: new("12:cpuset:/docker/abc\n0::/system.slice/docker-abc.scope\n"),
			path:    "/system.slice/docker-abc.scope",
		},
		"cgroup_v1_only": {
			content: new("12:cpuset:/docker/abc\n1:name=systemd:/docker/abc\n"),
		},
		"path_with_space": {
			content: new("0::/deleted cgroup (deleted)\n"),
		},
		"relative_path": {
			content: new("0::abc\n"),
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			filePath := filepath.Join(t.TempDir(), "cgroup")
			if testCase.content != nil {
				err := os.WriteFile(filePath, []byte(*testCase.content), 0o600)
				require.NoError(t, err)
			}

			path := readCgroupPath(filePath)

			assert.Equal(t, testCase.path, path)
		})
	}
}

func Test_Config_AllowOutputTemporarily_revertAfterSetEnabledFalse(t *testing.T) {
	t.Parallel()
	ctrl := gomock.NewController(t)

	ctx := context.Background()
	impl := NewMockfirewallImpl(ctrl)
	impl.EXPECT().AcceptOutputMarked(ctx, "tcp", "eth0", netip.MustParseAddr("1.1.1.1"),
		uint16(443), "/", uint32(1), false).Return(nil)
	logger := NewMockLogger(ctrl)
	disablingCall := logger.EXPECT().Info("disabling...")
	logger.EXPECT().Info("disabled successfully").After(disablingCall)
	restoreCalls := 0
	config := &Config{
		impl:          impl,
		logger:        logger,
		enabled:       true,
		defaultRoutes: []routing.DefaultRoute{{NetInterface: "eth0"}},
		cgroupPath:    "/",
		restore:       func(context.Context) { restoreCalls++ },
	}

	addrPorts := []netip.AddrPort{netip.MustParseAddrPort("1.1.1.1:443")}
	revert, err := config.AllowOutputTemporarily(ctx, "tcp", 1, addrPorts)
	require.NoError(t, err)

	err = config.SetEnabled(ctx, false)
	require.NoError(t, err)
	assert.Equal(t, 1, restoreCalls)

	// Simulate the firewall being enabled again, which does not
	// restore the temporary rules removed when disabling it.
	config.enabled = true

	// The rules are already removed, so no removal is attempted.
	err = revert(ctx)
	assert.NoError(t, err)
}
