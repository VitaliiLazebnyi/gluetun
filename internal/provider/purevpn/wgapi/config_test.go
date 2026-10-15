package wgapi

import (
	"net/netip"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_parseConfig(t *testing.T) {
	t.Parallel()

	testCases := map[string]struct {
		content    string
		config     Config
		errMessage string
	}{
		"full": {
			content: "[Interface]\nPrivateKey = {clientPrivateKey}\n" +
				"Address = 10.14.0.3/32, fd00::3/128\nDNS = 1.1.1.1\n\n" +
				"[Peer]\n# comment\nPublicKey = " + testServerKey + "\n" +
				"AllowedIPs = 0.0.0.0/0\nEndpoint = 198.51.100.1:51820\n",
			config: Config{
				Addresses: []netip.Prefix{
					netip.MustParsePrefix("10.14.0.3/32"),
					netip.MustParsePrefix("fd00::3/128"),
				},
				DNS:             []netip.Addr{netip.MustParseAddr("1.1.1.1")},
				ServerPublicKey: testServerKey,
				EndpointHost:    "198.51.100.1",
				EndpointPort:    51820,
			},
		},
		"keepalive": {
			content: "[Interface]\nAddress=172.21.6.133\n[Peer]\nPublicKey=" + testServerKey +
				"\nEndpoint=host.example:51820\nPersistentKeepalive=25",
			config: Config{
				Addresses:           []netip.Prefix{netip.MustParsePrefix("172.21.6.133/32")},
				ServerPublicKey:     testServerKey,
				EndpointHost:        "host.example",
				EndpointPort:        51820,
				PersistentKeepalive: 25 * time.Second,
			},
		},
		"missing_address": {
			content:    "[Peer]\nPublicKey=" + testServerKey + "\nEndpoint=1.2.3.4:51820",
			errMessage: "interface address is missing",
		},
		"invalid_public_key": {
			content:    "[Interface]\nAddress=10.0.0.1\n[Peer]\nPublicKey=abc\nEndpoint=1.2.3.4:51820",
			errMessage: "parsing peer publickey: wgtypes: failed to parse base64-encoded key",
		},
		"missing_endpoint": {
			content:    "[Interface]\nAddress=10.0.0.1\n[Peer]\nPublicKey=" + testServerKey,
			errMessage: "peer endpoint is missing",
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			config, err := parseConfig(testCase.content)
			if testCase.errMessage != "" {
				require.Error(t, err)
				assert.ErrorContains(t, err, testCase.errMessage)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, testCase.config, config)
		})
	}
}

func Test_Config_EndpointIP(t *testing.T) {
	t.Parallel()

	ip, ok := Config{EndpointHost: "host.example", ProtocolIP: "203.0.113.7"}.EndpointIP()
	assert.True(t, ok)
	assert.Equal(t, netip.MustParseAddr("203.0.113.7"), ip)

	ip, ok = Config{EndpointHost: "198.51.100.1"}.EndpointIP()
	assert.True(t, ok)
	assert.Equal(t, netip.MustParseAddr("198.51.100.1"), ip)

	_, ok = Config{EndpointHost: "host.example"}.EndpointIP()
	assert.False(t, ok)
}
