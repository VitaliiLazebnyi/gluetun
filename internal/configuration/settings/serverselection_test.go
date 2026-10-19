package settings

import (
	"testing"

	"github.com/qdm12/gluetun/internal/constants/providers"
	"github.com/qdm12/gluetun/internal/constants/vpn"
	"github.com/qdm12/gluetun/internal/models"
	"github.com/qdm12/gosettings/validate"
	"github.com/stretchr/testify/assert"
	"go.uber.org/mock/gomock"
)

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
			filterChoicesGetter := NewMockFilterChoicesGetter(ctrl)
			if testCase.errMessage == "" {
				filterChoicesGetter.EXPECT().GetFilterChoices(providers.Mullvad).
					Return(models.FilterChoices{}).Times(1)
			}
			warner := NewMockWarner(ctrl)

			ss := ServerSelection{}.WithDefaults(providers.Mullvad)
			ss.Mode = testCase.mode

			err := ss.validate(providers.Mullvad, filterChoicesGetter, warner)

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
		provider string
		vpnType  string
		// selection is the server selection to validate, with its
		// VPN type set to vpnType and its defaults set.
		selection ServerSelection
		// usesFilterChoices is true if the location filters are
		// validated against the servers data filter choices.
		usesFilterChoices bool
		warning           string
		errWrapped        error
		errMessage        string
	}{
		"purevpn_wireguard_one_country": {
			provider:  providers.Purevpn,
			vpnType:   vpn.Wireguard,
			selection: ServerSelection{Countries: []string{"Germany"}},
		},
		"purevpn_wireguard_lowercase_country": {
			provider:  providers.Purevpn,
			vpnType:   vpn.Wireguard,
			selection: ServerSelection{Countries: []string{"united kingdom"}},
		},
		"purevpn_wireguard_country_not_in_servers_data": {
			provider:  providers.Purevpn,
			vpnType:   vpn.Wireguard,
			selection: ServerSelection{Countries: []string{"Japan"}},
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
			selection: ServerSelection{Countries: []string{"Germany", "France"}},
			errMessage: "for VPN service provider purevpn: " +
				"exactly one country must be set with PureVPN Wireguard, but got 2: Germany, France",
		},
		"purevpn_wireguard_unknown_country": {
			provider:   providers.Purevpn,
			vpnType:    vpn.Wireguard,
			selection:  ServerSelection{Countries: []string{"Atlantis"}},
			errMessage: `for VPN service provider purevpn: country code not found for country "Atlantis"`,
		},
		"purevpn_wireguard_ignored_city": {
			provider:  providers.Purevpn,
			vpnType:   vpn.Wireguard,
			selection: ServerSelection{Countries: []string{"Germany"}, Cities: []string{"Berlin"}},
			warning: "server selection filters cities are ignored with PureVPN Wireguard, " +
				"use PUREVPN_CITY_ID to select a city",
		},
		"purevpn_wireguard_ignored_city_not_in_servers_data": {
			provider:  providers.Purevpn,
			vpnType:   vpn.Wireguard,
			selection: ServerSelection{Countries: []string{"Germany"}, Cities: []string{"Atlantis City"}},
			warning: "server selection filters cities are ignored with PureVPN Wireguard, " +
				"use PUREVPN_CITY_ID to select a city",
		},
		"purevpn_wireguard_ignored_filters": {
			provider: providers.Purevpn,
			vpnType:  vpn.Wireguard,
			selection: ServerSelection{
				Countries: []string{"United States"}, Regions: []string{"region"},
				Cities: []string{"New York"}, ISPs: []string{"isp"}, Names: []string{"name"},
				Numbers: []uint16{1}, Hostnames: []string{"host"}, Categories: []string{"category"},
			},
			warning: "server selection filters regions, cities, ISPs, names, numbers, hostnames, " +
				"categories are ignored with PureVPN Wireguard, use PUREVPN_CITY_ID to select a city",
		},
		"purevpn_openvpn_no_country": {
			provider:          providers.Purevpn,
			vpnType:           vpn.OpenVPN,
			usesFilterChoices: true,
		},
		"purevpn_openvpn_two_countries_and_city": {
			provider:          providers.Purevpn,
			vpnType:           vpn.OpenVPN,
			selection:         ServerSelection{Countries: []string{"Germany", "France"}, Cities: []string{"Berlin"}},
			usesFilterChoices: true,
		},
		"purevpn_openvpn_country_not_in_servers_data": {
			provider:          providers.Purevpn,
			vpnType:           vpn.OpenVPN,
			selection:         ServerSelection{Countries: []string{"Japan"}},
			usesFilterChoices: true,
			errWrapped:        validate.ErrValueNotOneOf,
			errMessage: "for VPN service provider purevpn: the country specified is not valid: " +
				"value is not one of the possible choices: none of Japan is one of the choices available Germany, France",
		},
		"mullvad_wireguard_no_country": {
			provider:          providers.Mullvad,
			vpnType:           vpn.Wireguard,
			usesFilterChoices: true,
		},
		"mullvad_wireguard_two_countries_and_city": {
			provider:          providers.Mullvad,
			vpnType:           vpn.Wireguard,
			selection:         ServerSelection{Countries: []string{"Germany", "France"}, Cities: []string{"Berlin"}},
			usesFilterChoices: true,
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			ctrl := gomock.NewController(t)

			filterChoicesGetter := NewMockFilterChoicesGetter(ctrl)
			if testCase.usesFilterChoices {
				filterChoicesGetter.EXPECT().GetFilterChoices(testCase.provider).
					Return(filterChoices).Times(1)
			}
			warner := NewMockWarner(ctrl)
			if testCase.warning != "" {
				warner.EXPECT().Warn(testCase.warning).Times(1)
			}

			serverSelection := testCase.selection
			serverSelection.VPN = testCase.vpnType
			serverSelection = serverSelection.WithDefaults(testCase.provider)

			err := serverSelection.validate(testCase.provider, filterChoicesGetter, warner)

			if testCase.errWrapped != nil {
				assert.ErrorIs(t, err, testCase.errWrapped)
			}
			if testCase.errMessage == "" {
				assert.NoError(t, err)
				return
			}
			assert.ErrorContains(t, err, testCase.errMessage)
		})
	}
}
