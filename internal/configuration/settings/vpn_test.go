package settings

import (
	"testing"

	"github.com/qdm12/gluetun/internal/constants/providers"
	"github.com/qdm12/gluetun/internal/constants/vpn"
	"github.com/qdm12/gluetun/internal/models"
	"github.com/stretchr/testify/assert"
	"go.uber.org/mock/gomock"
)

func Test_VPN_Validate_purevpn(t *testing.T) {
	t.Parallel()

	testCases := map[string]struct {
		vpnType    string
		pureVPN    PureVPN
		errMessage string
	}{
		"wireguard_without_purevpn_credentials": {
			vpnType:    vpn.Wireguard,
			errMessage: "PureVPN settings: account username and password, or session token, are not set",
		},
		"wireguard_with_purevpn_session_token": {
			vpnType: vpn.Wireguard,
			pureVPN: PureVPN{SessionToken: new("token")},
		},
		"openvpn_without_purevpn_credentials": {
			vpnType: vpn.OpenVPN,
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			ctrl := gomock.NewController(t)

			filterChoices := models.FilterChoices{Countries: []string{"Germany"}}
			filterChoicesGetter := NewMockFilterChoicesGetter(ctrl)
			filterChoicesGetter.EXPECT().GetFilterChoices(providers.Purevpn).
				Return(filterChoices).Times(1)
			warner := NewMockWarner(ctrl)

			settings := VPN{
				Type: testCase.vpnType,
				Provider: Provider{
					Name: providers.Purevpn,
					ServerSelection: ServerSelection{
						VPN:       testCase.vpnType,
						Countries: []string{"Germany"},
					},
				},
				OpenVPN: OpenVPN{User: new("user"), Password: new("password")},
				PureVPN: testCase.pureVPN,
			}
			settings.setDefaults()

			const ipv6Supported = false
			err := settings.Validate(filterChoicesGetter, ipv6Supported, warner)

			if testCase.errMessage == "" {
				assert.NoError(t, err)
				return
			}
			assert.ErrorContains(t, err, testCase.errMessage)
		})
	}
}
