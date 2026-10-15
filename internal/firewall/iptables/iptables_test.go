package iptables

import (
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_acceptOutputMarkedInstruction(t *testing.T) {
	t.Parallel()

	testCases := map[string]struct {
		remove      bool
		instruction string
		operation   operation
	}{
		"append": {
			instruction: "--append OUTPUT -d 104.18.1.2 -o eth0 -p tcp -m tcp --dport 443 " +
				"-m mark --mark 28789 -j ACCEPT",
			operation: opAppend,
		},
		"delete": {
			remove: true,
			instruction: "--delete OUTPUT -d 104.18.1.2 -o eth0 -p tcp -m tcp --dport 443 " +
				"-m mark --mark 28789 -j ACCEPT",
			operation: opDelete,
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			instruction := acceptOutputMarkedInstruction("tcp", "eth0",
				netip.MustParseAddr("104.18.1.2"), 443, 0x7075, testCase.remove)

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
				mark:            mark{value: 0x7075},
			}, parsed)

			const listOutput = `Chain OUTPUT (policy DROP 0 packets, 0 bytes)
num pkts bytes target     prot opt in     out     source               destination
1   0     0 ACCEPT     6    --  *      eth0    0.0.0.0/0            104.18.1.2           tcp dpt:443 mark match 0x7075
`
			listed, err := parseChain(listOutput)
			require.NoError(t, err)
			require.Len(t, listed.rules, 1)
			assert.True(t, parsed.equalToRule("filter", "OUTPUT", listed.rules[0]))
		})
	}
}
