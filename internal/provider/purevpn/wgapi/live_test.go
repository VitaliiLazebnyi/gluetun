package wgapi

import (
	"bufio"
	"context"
	"net/http"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// Test_Live talks to the real PureVPN website and only runs if the
// PUREVPN_LIVE_TEST environment variable is set to the path of an env
// file such as purevpn-wireguard.env at the repository root, for example:
//
//	PUREVPN_LIVE_TEST=$PWD/purevpn-wireguard.env go test -run Test_Live -v ./internal/provider/purevpn/wgapi/
//
// It logs in, fetches a Wireguard configuration and prints it, without
// the private key. Set PUREVPN_LIVE_EXPECT=invalid_credentials to check
// that fake credentials are rejected as such.
// It does not run in parallel to avoid concurrent requests to the real website.
func Test_Live(t *testing.T) { //nolint:paralleltest
	envPath := os.Getenv("PUREVPN_LIVE_TEST")
	if envPath == "" {
		t.Skip("PUREVPN_LIVE_TEST is not set")
	}
	env := readEnvFile(t, envPath)

	session := Session{}
	token := env["PUREVPN_SESSION_TOKEN"]
	switch {
	case token == "":
	case IsJWT(token):
		session.AccessToken = token
	default:
		session.AuthCookies = map[string]string{"fusionauth.sso": token}
	}
	credentials := Credentials{
		Username:   env["PUREVPN_USERNAME"],
		Password:   env["PUREVPN_PASSWORD"],
		TOTPSecret: env["PUREVPN_TOTP_SECRET"],
	}
	client, err := New(&http.Client{Timeout: 30 * time.Second}, "", "", credentials, session)
	require.NoError(t, err)

	key, err := wgtypes.GeneratePrivateKey()
	require.NoError(t, err)
	var cityID uint64
	if env["PUREVPN_CITY_ID"] != "" {
		cityID, err = strconv.ParseUint(env["PUREVPN_CITY_ID"], 10, 32)
		require.NoError(t, err)
	}

	config, err := client.FetchConfig(context.Background(), ServerRequest{
		CountryCode:     env["PUREVPN_COUNTRY"],
		CityID:          uint(cityID),
		SubscriptionID:  env["PUREVPN_SUBSCRIPTION_ID"],
		VPNUsername:     env["PUREVPN_VPN_USERNAME"],
		ClientPublicKey: key.PublicKey().String(),
	})
	if os.Getenv("PUREVPN_LIVE_EXPECT") == "invalid_credentials" {
		require.ErrorIs(t, err, errInvalidCredentials)
		t.Logf("rejected as expected: %s", err)
		return
	}
	require.NoError(t, err)
	t.Logf("configuration: %+v", config)
	t.Logf("session cookies stored: %d", len(client.Session().AuthCookies))
}

func readEnvFile(t *testing.T, path string) map[string]string {
	t.Helper()
	file, err := os.Open(path) //nolint:gosec // path set by the developer running the test
	require.NoError(t, err)
	defer file.Close()

	env := make(map[string]string)
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, value, found := strings.Cut(line, "=")
		if !found {
			continue
		}
		env[strings.TrimSpace(key)] = strings.Trim(strings.TrimSpace(value), `"'`)
	}
	require.NoError(t, scanner.Err())
	return env
}
