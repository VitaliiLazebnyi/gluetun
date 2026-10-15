package server

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/qdm12/gluetun/internal/configuration/settings"
	"github.com/qdm12/gluetun/internal/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
)

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
		"nil_secrets_not_redacted": {
			settings: settings.VPN{PureVPN: settings.PureVPN{Country: "US"}},
			purevpn: map[string]any{
				"username":        nil,
				"password":        nil,
				"totp_secret":     nil,
				"session_token":   nil,
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
			ctrl := gomock.NewController(t)

			looper := NewMockVPNLooper(ctrl)
			looper.EXPECT().GetSettings().Return(testCase.settings.Copy())
			handler := newVPNHandler(context.Background(), looper, nil, false, NewMockLogger(ctrl))
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

func Test_vpnHandler_PureVPN_secrets_roundTrip(t *testing.T) {
	t.Parallel()
	ctrl := gomock.NewController(t)

	var allSettings settings.Settings
	allSettings.VPN = newPureVPNTestSettings("JBSWY3DP", "token")
	allSettings.VPN.Type = "wireguard"
	allSettings.VPN.Provider.Name = "purevpn"
	allSettings.SetDefaults()
	current := allSettings.VPN

	ctx := context.Background()
	looper := NewMockVPNLooper(ctrl)
	storage := NewMockStorage(ctrl)
	logger := NewMockLogger(ctrl)
	handler := newVPNHandler(ctx, looper, storage, false, logger)

	// A client gets the settings, with the secrets redacted.
	looper.EXPECT().GetSettings().Return(current.Copy())
	request := httptest.NewRequestWithContext(ctx, http.MethodGet, "/vpn/settings", nil)
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	require.Equal(t, http.StatusOK, recorder.Code)
	var got map[string]any
	err := json.Unmarshal(recorder.Body.Bytes(), &got)
	require.NoError(t, err)
	purevpn, ok := got["purevpn"].(map[string]any)
	require.True(t, ok)
	assert.Equal(t, redactedSecret, purevpn["password"])
	assert.Equal(t, redactedSecret, purevpn["totp_secret"])
	assert.Equal(t, redactedSecret, purevpn["session_token"])
	assert.NotContains(t, recorder.Body.String(), "JBSWY3DP")

	putSettings := func(body map[string]any) (response string) {
		t.Helper()
		data, err := json.Marshal(body)
		require.NoError(t, err)
		request := httptest.NewRequestWithContext(ctx, http.MethodPut, "/vpn/settings", bytes.NewReader(data))
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, request)
		require.Equal(t, http.StatusOK, recorder.Code, recorder.Body.String())
		return recorder.Body.String()
	}

	// The client puts back the settings received with another country:
	// the redacted secrets are kept unchanged.
	purevpn["country"] = "GB"
	expected := current.Copy()
	expected.PureVPN.Country = "GB"
	looper.EXPECT().GetSettings().Return(current.Copy())
	storage.EXPECT().GetFilterChoices("purevpn").Return(models.FilterChoices{})
	looper.EXPECT().SetSettings(ctx, expected).Return("settings updated")
	assert.Equal(t, "settings updated", putSettings(got))

	// The client puts a new password: it is changed.
	purevpn["password"] = "new-password"
	current = expected
	expected = current.Copy()
	expected.PureVPN.Password = new("new-password")
	looper.EXPECT().GetSettings().Return(current.Copy())
	storage.EXPECT().GetFilterChoices("purevpn").Return(models.FilterChoices{})
	looper.EXPECT().SetSettings(ctx, expected).Return("settings updated")
	assert.Equal(t, "settings updated", putSettings(got))
}
