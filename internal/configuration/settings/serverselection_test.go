package settings

import (
	"testing"

	"github.com/qdm12/gluetun/internal/constants/providers"
	"github.com/qdm12/gluetun/internal/constants/vpn"
	"github.com/qdm12/gluetun/internal/models"
	"github.com/stretchr/testify/assert"
	"go.uber.org/mock/gomock"
)

type noopFilterChoicesGetter struct{}

func (noopFilterChoicesGetter) GetFilterChoices(string) models.FilterChoices {
	return models.FilterChoices{}
}

func Test_ServerSelection_setDefaults_mode(t *testing.T) {
	t.Parallel()

	testCases := map[string]struct {
		initial  ServerSelection
		expected string
	}{
		"empty_mode_set_to_random": {
			expected: "random",
		},
		"random_mode_kept": {
			initial:  ServerSelection{Mode: "random"},
			expected: "random",
		},
		"ordered_mode_kept": {
			initial:  ServerSelection{Mode: "ordered"},
			expected: "ordered",
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			testCase.initial.setDefaults(providers.Mullvad, false)

			assert.Equal(t, testCase.expected, testCase.initial.Mode)
		})
	}
}

func Test_ServerSelection_validate_mode(t *testing.T) {
	t.Parallel()

	testCases := map[string]struct {
		mode       string
		errMessage string
	}{
		"random": {
			mode: "random",
		},
		"ordered": {
			mode: "ordered",
		},
		"empty": {
			errMessage: "the selection mode specified is not valid",
		},
		"invalid": {
			mode:       "invalid",
			errMessage: "the selection mode specified is not valid",
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			ctrl := gomock.NewController(t)
			warner := NewMockWarner(ctrl)

			ss := ServerSelection{}.WithDefaults(providers.Mullvad)
			ss.Mode = testCase.mode

			err := ss.validate(providers.Mullvad, noopFilterChoicesGetter{}, warner)

			if testCase.errMessage != "" {
				assert.ErrorContains(t, err, testCase.errMessage)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func Test_ServerSelection_validate_pureVPNWireguard(t *testing.T) {
	t.Parallel()

	filterChoices := models.FilterChoices{
		Countries: []string{"Germany", "France"},
		Cities:    []string{"Berlin"},
	}

	testCases := map[string]struct {
		provider   string
		vpnType    string
		countries  []string
		cities     []string
		warning    string
		errMessage string
	}{
		"purevpn_wireguard_one_country": {
			provider:  providers.Purevpn,
			vpnType:   vpn.Wireguard,
			countries: []string{"Germany"},
		},
		"purevpn_wireguard_no_country": {
			provider: providers.Purevpn,
			vpnType:  vpn.Wireguard,
			errMessage: "for VPN service provider purevpn: " +
				"exactly one country must be set with PureVPN Wireguard, but got none",
		},
		"purevpn_wireguard_two_countries": {
			provider:  providers.Purevpn,
			vpnType:   vpn.Wireguard,
			countries: []string{"Germany", "France"},
			errMessage: "for VPN service provider purevpn: " +
				"exactly one country must be set with PureVPN Wireguard, but got 2: Germany, France",
		},
		"purevpn_wireguard_ignored_city": {
			provider:  providers.Purevpn,
			vpnType:   vpn.Wireguard,
			countries: []string{"Germany"},
			cities:    []string{"Berlin"},
			warning: "server selection filters cities are ignored with PureVPN Wireguard, " +
				"use PUREVPN_CITY_ID to select a city",
		},
		"purevpn_openvpn_no_country": {
			provider: providers.Purevpn,
			vpnType:  vpn.OpenVPN,
		},
		"purevpn_openvpn_two_countries_and_city": {
			provider:  providers.Purevpn,
			vpnType:   vpn.OpenVPN,
			countries: []string{"Germany", "France"},
			cities:    []string{"Berlin"},
		},
		"mullvad_wireguard_no_country": {
			provider: providers.Mullvad,
			vpnType:  vpn.Wireguard,
		},
		"mullvad_wireguard_two_countries_and_city": {
			provider:  providers.Mullvad,
			vpnType:   vpn.Wireguard,
			countries: []string{"Germany", "France"},
			cities:    []string{"Berlin"},
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			ctrl := gomock.NewController(t)

			filterChoicesGetter := NewMockFilterChoicesGetter(ctrl)
			filterChoicesGetter.EXPECT().GetFilterChoices(testCase.provider).
				Return(filterChoices).Times(1)
			warner := NewMockWarner(ctrl)
			if testCase.warning != "" {
				warner.EXPECT().Warn(testCase.warning).Times(1)
			}

			serverSelection := ServerSelection{
				VPN:       testCase.vpnType,
				Countries: testCase.countries,
				Cities:    testCase.cities,
			}.WithDefaults(testCase.provider)

			err := serverSelection.validate(testCase.provider, filterChoicesGetter, warner)

			if testCase.errMessage == "" {
				assert.NoError(t, err)
				return
			}
			assert.ErrorContains(t, err, testCase.errMessage)
		})
	}
}
