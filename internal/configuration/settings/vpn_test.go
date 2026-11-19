package settings

import (
	"testing"

	"github.com/qdm12/gluetun/internal/constants/providers"
	"github.com/qdm12/gluetun/internal/constants/vpn"
	"github.com/qdm12/gluetun/internal/models"
	"github.com/qdm12/gosettings/reader"
	"github.com/qdm12/gosettings/reader/sources/env"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
)

func Test_VPN_Validate(t *testing.T) {
	t.Parallel()

	testCases := map[string]struct {
		vpnType string
		pureVPN PureVPN
		// usesFilterChoices is true if the location filters are
		// validated against the servers data filter choices.
		usesFilterChoices bool
		errMessage        string
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
			vpnType:           vpn.OpenVPN,
			usesFilterChoices: true,
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			ctrl := gomock.NewController(t)

			filterChoicesGetter := NewMockFilterChoicesGetter(ctrl)
			if testCase.usesFilterChoices {
				filterChoices := models.FilterChoices{Countries: []string{"Germany"}}
				filterChoicesGetter.EXPECT().GetFilterChoices(providers.Purevpn).
					Return(filterChoices)
			}
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

func Test_VPN_Copy(t *testing.T) {
	t.Parallel()

	settings := VPN{PureVPN: PureVPN{Username: new("user@example.com"), SessionToken: new("token")}}

	copied := settings.Copy()

	assert.Equal(t, settings.PureVPN, copied.PureVPN)
}

func Test_VPN_OverrideWith(t *testing.T) {
	t.Parallel()

	settings := VPN{PureVPN: PureVPN{Username: new("user@example.com"), SessionToken: new("token")}}
	other := VPN{PureVPN: PureVPN{SessionToken: new("other-token")}}

	settings.OverrideWith(other)

	expected := PureVPN{Username: new("user@example.com"), SessionToken: new("other-token")}
	assert.Equal(t, expected, settings.PureVPN)
}

func Test_VPN_toLinesNode(t *testing.T) {
	t.Parallel()

	testCases := map[string]struct {
		vpnType      string
		providerName string
		showsPureVPN bool
	}{
		"purevpn_wireguard": {
			vpnType:      vpn.Wireguard,
			providerName: providers.Purevpn,
			showsPureVPN: true,
		},
		"purevpn_openvpn": {
			vpnType:      vpn.OpenVPN,
			providerName: providers.Purevpn,
		},
		"other_provider_wireguard": {
			vpnType:      vpn.Wireguard,
			providerName: providers.Custom,
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			settings := VPN{
				Type:     testCase.vpnType,
				Provider: Provider{Name: testCase.providerName},
				PureVPN:  PureVPN{CityID: new(uint32(1234))},
			}
			settings.setDefaults()

			lines := settings.toLinesNode().String()

			if testCase.showsPureVPN {
				assert.Contains(t, lines, "PureVPN account settings:")
				assert.Contains(t, lines, "City ID: 1234")
			} else {
				assert.NotContains(t, lines, "PureVPN account settings:")
			}
		})
	}
}

func Test_VPN_read(t *testing.T) {
	t.Parallel()

	reader := reader.New(reader.Settings{
		Sources: []reader.Source{env.New(env.Settings{Environ: []string{
			"PUREVPN_USERNAME=User@Example.com",
		}})},
	})

	var settings VPN
	err := settings.read(reader)

	require.NoError(t, err)
	assert.Equal(t, new("User@Example.com"), settings.PureVPN.Username)
}
