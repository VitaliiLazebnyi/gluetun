package iptables

import (
	"context"
	"errors"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
)

func Test_acceptOutputMarkedInstruction(t *testing.T) {
	t.Parallel()

	testCases := map[string]struct {
		remove      bool
		cgroupPath  string
		instruction string
		operation   operation
		listOutput  string
	}{
		"append": {
			instruction: "--append OUTPUT -d 104.18.1.2 -o eth0 -p tcp -m tcp --dport 443 " +
				"-m mark --mark 28789 -j ACCEPT",
			operation: opAppend,
			listOutput: "1   0     0 ACCEPT     6    --  *      eth0    0.0.0.0/0            104.18.1.2" +
				"           tcp dpt:443 mark match 0x7075\n",
		},
		"delete": {
			remove: true,
			instruction: "--delete OUTPUT -d 104.18.1.2 -o eth0 -p tcp -m tcp --dport 443 " +
				"-m mark --mark 28789 -j ACCEPT",
			operation: opDelete,
			listOutput: "1   0     0 ACCEPT     6    --  *      eth0    0.0.0.0/0            104.18.1.2" +
				"           tcp dpt:443 mark match 0x7075\n",
		},
		"delete_with_cgroup": {
			remove:     true,
			cgroupPath: "/",
			instruction: "--delete OUTPUT -d 104.18.1.2 -o eth0 -p tcp -m tcp --dport 443 " +
				"-m cgroup --path / -m mark --mark 28789 -j ACCEPT",
			operation: opDelete,
			// Output from iptables v1.8.11, both nf_tables and legacy.
			listOutput: "1   0     0 ACCEPT     tcp  --  *      eth0    0.0.0.0/0            104.18.1.2" +
				"           tcp dpt:443 cgroup / mark match 0x7075\n",
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			instruction := acceptOutputMarkedInstruction("tcp", "eth0",
				netip.MustParseAddr("104.18.1.2"), 443, testCase.cgroupPath, "28789", testCase.remove)

			assert.Equal(t, testCase.instruction, instruction)

			// The instruction must be parsable and match the rule as listed
			// by iptables, for the delete instruction to find the rule.
			parsed, err := parseIptablesInstruction(instruction)
			require.NoError(t, err)
			assert.Equal(t, iptablesInstruction{
				table:           "filter",
				operation:       testCase.operation,
				chain:           "OUTPUT",
				target:          "ACCEPT",
				protocol:        "tcp",
				outputInterface: "eth0",
				destination:     netip.MustParsePrefix("104.18.1.2/32"),
				destinationPort: 443,
				cgroupPath:      testCase.cgroupPath,
				mark:            mark{value: 0x7075},
			}, parsed)

			listOutput := "Chain OUTPUT (policy DROP 0 packets, 0 bytes)\n" +
				"num pkts bytes target     prot opt in     out     source               destination\n" +
				testCase.listOutput
			listed, err := parseChain(listOutput)
			require.NoError(t, err)
			require.Len(t, listed.rules, 1)
			assert.True(t, parsed.equalToRule("filter", "OUTPUT", listed.rules[0]))
		})
	}
}

// newFakeIptables creates fake iptables-save and iptables-restore
// programs in a temporary directory, and returns the path of the
// iptables program in this directory, which itself does not exist.
func newFakeIptables(t *testing.T) (iptablesPath string) {
	t.Helper()
	directory := t.TempDir()
	iptablesPath = filepath.Join(directory, "iptables")
	err := os.WriteFile(iptablesPath+"-save", []byte("#!/bin/sh\necho '*filter'\necho COMMIT\n"), 0o700) //nolint:gosec
	require.NoError(t, err)
	err = os.WriteFile(iptablesPath+"-restore", []byte("#!/bin/sh\ncat > /dev/null\n"), 0o700) //nolint:gosec
	require.NoError(t, err)
	return iptablesPath
}

func Test_Config_AcceptOutputMarked(t *testing.T) {
	t.Parallel()

	const appendCommand = " --append OUTPUT -d 1.2.3.4 -o eth0 -p tcp -m tcp --dport 443 " +
		"-m cgroup --path / -m mark --mark <redacted> -j ACCEPT"
	const deleteInstruction = "--delete OUTPUT -d 1.2.3.4 -o eth0 -p tcp -m tcp --dport 443 " +
		"-m cgroup --path / -m mark --mark <redacted> -j ACCEPT"
	const listHeader = "Chain OUTPUT (policy DROP 0 packets, 0 bytes)\n" +
		"num pkts bytes target     prot opt in     out     source               destination\n"

	testCases := map[string]struct {
		ip           netip.Addr
		remove       bool
		noIptables   bool
		cancelOnRun  bool
		makeRunner   func(ctrl *gomock.Controller, iptablesPath string) *MockCmdRunner
		makeLogger   func(ctrl *gomock.Controller, iptablesPath string) *MockLogger
		errMessage   string
		errWithPaths func(iptablesPath string) string
	}{
		"ipv6_address": {
			ip:         netip.MustParseAddr("2001:db8::1"),
			errMessage: "IP address is not IPv4: 2001:db8::1",
		},
		"saving_error": {
			ip:         netip.MustParseAddr("1.2.3.4"),
			noIptables: true,
			errMessage: "saving IPv4 iptables: running ",
		},
		"append_success": {
			ip: netip.MustParseAddr("1.2.3.4"),
			makeRunner: func(ctrl *gomock.Controller, iptablesPath string) *MockCmdRunner {
				runner := NewMockCmdRunner(ctrl)
				runner.EXPECT().Run(newCmdMatcher(iptablesPath, "^--append$", "^OUTPUT$",
					"^-d$", `^1\.2\.3\.4$`, "^-o$", "^eth0$", "^-p$", "^tcp$", "^-m$", "^tcp$",
					"^--dport$", "^443$", "^-m$", "^cgroup$", "^--path$", "^/$",
					"^-m$", "^mark$", "^--mark$", "^4660$", "^-j$", "^ACCEPT$")).
					Return("", nil)
				return runner
			},
			makeLogger: func(ctrl *gomock.Controller, iptablesPath string) *MockLogger {
				logger := NewMockLogger(ctrl)
				logger.EXPECT().Debug(iptablesPath + appendCommand)
				return logger
			},
		},
		"append_error_restores_with_canceled_context": {
			ip:          netip.MustParseAddr("1.2.3.4"),
			cancelOnRun: true,
			makeLogger: func(ctrl *gomock.Controller, iptablesPath string) *MockLogger {
				logger := NewMockLogger(ctrl)
				logger.EXPECT().Debug(iptablesPath + appendCommand)
				return logger
			},
			errWithPaths: func(iptablesPath string) string {
				return "command failed: \"" + iptablesPath + appendCommand + "\": test output: test error"
			},
		},
		"delete_found": {
			ip:     netip.MustParseAddr("1.2.3.4"),
			remove: true,
			makeRunner: func(ctrl *gomock.Controller, iptablesPath string) *MockCmdRunner {
				runner := NewMockCmdRunner(ctrl)
				runner.EXPECT().Run(newCmdMatcherListRules(iptablesPath, "filter", "OUTPUT")).
					Return(listHeader+"1   0     0 ACCEPT     tcp  --  *      eth0    0.0.0.0/0            "+
						"1.2.3.4              tcp dpt:443 cgroup / mark match 0x1234\n", nil)
				runner.EXPECT().Run(newCmdMatcher(iptablesPath, "^-t$", "^filter$",
					"^-D$", "^OUTPUT$", "^1$")).Return("", nil)
				return runner
			},
			makeLogger: func(ctrl *gomock.Controller, iptablesPath string) *MockLogger {
				logger := NewMockLogger(ctrl)
				logger.EXPECT().Debug(iptablesPath + " -t filter -L OUTPUT --line-numbers -n -v")
				logger.EXPECT().Debug("found iptables chain rule matching \"" + deleteInstruction +
					"\" at line number 1")
				logger.EXPECT().Debug(iptablesPath + " -t filter -D OUTPUT 1")
				return logger
			},
		},
		"delete_not_found": {
			ip:     netip.MustParseAddr("1.2.3.4"),
			remove: true,
			makeRunner: func(ctrl *gomock.Controller, iptablesPath string) *MockCmdRunner {
				runner := NewMockCmdRunner(ctrl)
				runner.EXPECT().Run(newCmdMatcherListRules(iptablesPath, "filter", "OUTPUT")).
					Return(listHeader+"1   0     0 ACCEPT     tcp  --  *      eth0    0.0.0.0/0            "+
						"1.2.3.4              tcp dpt:443 mark match 0x1234\n", nil)
				return runner
			},
			makeLogger: func(ctrl *gomock.Controller, iptablesPath string) *MockLogger {
				logger := NewMockLogger(ctrl)
				logger.EXPECT().Debug(iptablesPath + " -t filter -L OUTPUT --line-numbers -n -v")
				logger.EXPECT().Debug("rule matching \"" + deleteInstruction + "\" not found")
				return logger
			},
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			ctrl := gomock.NewController(t)

			iptablesPath := filepath.Join(t.TempDir(), "iptables")
			if !testCase.noIptables {
				iptablesPath = newFakeIptables(t)
			}
			ctx, cancel := context.WithCancel(context.Background())
			t.Cleanup(cancel)

			var runner *MockCmdRunner
			if testCase.makeRunner != nil {
				runner = testCase.makeRunner(ctrl, iptablesPath)
			}
			if testCase.cancelOnRun {
				runner = NewMockCmdRunner(ctrl)
				runner.EXPECT().Run(newCmdMatcher(iptablesPath, "^--append$", "^OUTPUT$",
					"^-d$", `^1\.2\.3\.4$`, "^-o$", "^eth0$", "^-p$", "^tcp$", "^-m$", "^tcp$",
					"^--dport$", "^443$", "^-m$", "^cgroup$", "^--path$", "^/$",
					"^-m$", "^mark$", "^--mark$", "^4660$", "^-j$", "^ACCEPT$")).
					DoAndReturn(func(*exec.Cmd) (string, error) {
						// The rule may be added before the context is canceled.
						cancel()
						return "test output", errors.New("test error")
					})
				// The restore must run even though the context is canceled,
				// otherwise it fails and a warning is logged.
				runner.EXPECT().Run(newCmdMatcher(iptablesPath + "-restore")).
					DoAndReturn(func(cmd *exec.Cmd) (string, error) {
						output, err := cmd.CombinedOutput()
						return string(output), err
					})
			}
			var logger *MockLogger
			if testCase.makeLogger != nil {
				logger = testCase.makeLogger(ctrl, iptablesPath)
			}
			config := &Config{
				runner:   runner,
				logger:   logger,
				ipTables: iptablesPath,
			}

			err := config.AcceptOutputMarked(ctx, "tcp", "eth0", testCase.ip, 443, "/", 0x1234, testCase.remove)

			switch {
			case testCase.errWithPaths != nil:
				assert.ErrorContains(t, err, testCase.errWithPaths(iptablesPath))
				assert.NotContains(t, err.Error(), "4660")
			case testCase.errMessage != "":
				assert.ErrorContains(t, err, testCase.errMessage)
			default:
				assert.NoError(t, err)
			}
		})
	}
}

func Test_Config_runIptablesInstructionNoSave(t *testing.T) {
	t.Parallel()

	testCases := map[string]struct {
		output     string
		runErr     error
		errWrapped error
		errMessage string
	}{
		"success": {},
		"kernel_module_missing": {
			output:     "Extension cgroup revision 0 not supported, missing kernel module?",
			runErr:     errors.New("exit status 1"),
			errWrapped: ErrKernelModuleMissing,
			errMessage: "command failed: \"/sbin/iptables --append INPUT -j ACCEPT\": " +
				"Extension cgroup revision 0 not supported, missing kernel module?: " +
				"kernel module is missing for this operation",
		},
		"other_error": {
			output: "test output",
			runErr: errors.New("exit status 1"),
			errMessage: "command failed: \"/sbin/iptables --append INPUT -j ACCEPT\": " +
				"test output: exit status 1",
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			ctrl := gomock.NewController(t)

			const iptablesBinary = "/sbin/iptables"
			runner := NewMockCmdRunner(ctrl)
			runner.EXPECT().Run(newCmdMatcher(iptablesBinary, "^--append$", "^INPUT$", "^-j$", "^ACCEPT$")).
				Return(testCase.output, testCase.runErr)
			logger := NewMockLogger(ctrl)
			logger.EXPECT().Debug("/sbin/iptables --append INPUT -j ACCEPT")
			config := &Config{runner: runner, logger: logger, ipTables: iptablesBinary}

			err := config.runIptablesInstructionNoSave(context.Background(), "--append INPUT -j ACCEPT")

			if testCase.errWrapped != nil {
				assert.ErrorIs(t, err, testCase.errWrapped)
			}
			if testCase.errMessage != "" {
				assert.EqualError(t, err, testCase.errMessage)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}
