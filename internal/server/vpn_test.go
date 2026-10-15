package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/qdm12/gluetun/internal/configuration/settings"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type fakeVPNLooper struct {
	VPNLooper
	settings settings.VPN
}

func (l *fakeVPNLooper) GetSettings() settings.VPN {
	return l.settings.Copy()
}

type noopWarner struct{}

func (noopWarner) Warn(string) {}

func newPureVPNTestSettings(totpSecret, sessionToken string) settings.VPN {
	return settings.VPN{
		PureVPN: settings.PureVPN{
			Username:     new("user@example.com"),
			Password:     new("password"),
			TOTPSecret:   &totpSecret,
			SessionToken: &sessionToken,
			Country:      "US",
		},
	}
}

func Test_vpnHandler_getSettings_redactsPureVPNSecrets(t *testing.T) {
	t.Parallel()

	testCases := map[string]struct {
		settings settings.VPN
		purevpn  map[string]any
	}{
		"secrets_set": {
			settings: newPureVPNTestSettings("JBSWY3DP", "token"),
			purevpn: map[string]any{
				"username":        "user@example.com",
				"password":        redactedSecret,
				"totp_secret":     redactedSecret,
				"session_token":   redactedSecret,
				"country":         "US",
				"city_id":         nil,
				"subscription_id": nil,
				"vpn_username":    nil,
			},
		},
		"empty_secrets_not_redacted": {
			settings: newPureVPNTestSettings("", ""),
			purevpn: map[string]any{
				"username":        "user@example.com",
				"password":        redactedSecret,
				"totp_secret":     "",
				"session_token":   "",
				"country":         "US",
				"city_id":         nil,
				"subscription_id": nil,
				"vpn_username":    nil,
			},
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			looper := &fakeVPNLooper{settings: testCase.settings}
			handler := newVPNHandler(context.Background(), looper, nil, false, noopWarner{})
			request := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/vpn/settings", nil)
			recorder := httptest.NewRecorder()

			handler.ServeHTTP(recorder, request)

			require.Equal(t, http.StatusOK, recorder.Code)
			var body struct {
				PureVPN map[string]any `json:"purevpn"`
			}
			err := json.Unmarshal(recorder.Body.Bytes(), &body)
			require.NoError(t, err)
			assert.Equal(t, testCase.purevpn, body.PureVPN)
			// The looper settings must not be modified.
			assert.Equal(t, testCase.settings, looper.settings)
		})
	}
}

func Test_PureVPN_secrets_roundTrip(t *testing.T) {
	t.Parallel()

	current := newPureVPNTestSettings("JBSWY3DP", "token")

	// A client gets the settings, changes the country and puts them back.
	got := current.Copy()
	redactPureVPNSecrets(&got)
	got.PureVPN.Country = "GB"
	data, err := json.Marshal(got)
	require.NoError(t, err)
	var put settings.VPN
	err = json.Unmarshal(data, &put)
	require.NoError(t, err)

	ignoreRedactedPureVPNSecrets(&put)
	updated := current.Copy()
	updated.OverrideWith(put)

	expected := newPureVPNTestSettings("JBSWY3DP", "token")
	expected.PureVPN.Country = "GB"
	assert.Equal(t, expected.PureVPN, updated.PureVPN)

	// A new secret value is applied.
	put.PureVPN.Password = new("new-password")
	ignoreRedactedPureVPNSecrets(&put)
	updated.OverrideWith(put)
	assert.Equal(t, "new-password", *updated.PureVPN.Password)
}
