package settings

import (
	"net/netip"
	"testing"

	"github.com/qdm12/gluetun/internal/constants/providers"
	"github.com/stretchr/testify/assert"
)

func Test_WireguardSelection_validate_purevpn(t *testing.T) {
	t.Parallel()

	testCases := map[string]struct {
		selection  WireguardSelection
		errMessage string
	}{
		"defaults": {},
		"endpoint_ip_set": {
			selection:  WireguardSelection{EndpointIP: netip.MustParseAddr("203.0.113.1")},
			errMessage: "endpoint IP cannot be set for PureVPN",
		},
		"endpoint_port_set": {selection: WireguardSelection{EndpointPort: new(uint16(51820))}, errMessage: "endpoint port"},
		"public_key_set": {
			selection:  WireguardSelection{PublicKey: "Y0QnWR6mhgxOjNkPUkRdPYKYrB+pERhKFAuhkBapHw8="},
			errMessage: "public key cannot be set for PureVPN",
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			selection := testCase.selection
			selection.setDefaults()

			err := selection.validate(providers.Purevpn)

			if testCase.errMessage == "" {
				assert.NoError(t, err)
				return
			}
			assert.ErrorContains(t, err, testCase.errMessage)
		})
	}
}
