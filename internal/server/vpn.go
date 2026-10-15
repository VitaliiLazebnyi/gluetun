package server

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"

	"github.com/qdm12/gluetun/internal/configuration/settings"
)

func newVPNHandler(ctx context.Context, looper VPNLooper,
	storage Storage, ipv6Supported bool, w warner,
) http.Handler {
	return &vpnHandler{
		ctx:           ctx,
		looper:        looper,
		storage:       storage,
		ipv6Supported: ipv6Supported,
		warner:        w,
	}
}

type vpnHandler struct {
	ctx           context.Context //nolint:containedctx
	looper        VPNLooper
	storage       Storage
	ipv6Supported bool
	warner        warner
}

func (h *vpnHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	r.RequestURI = strings.TrimPrefix(r.RequestURI, "/vpn")
	switch r.RequestURI {
	case "/status":
		switch r.Method {
		case http.MethodGet:
			h.getStatus(w)
		case http.MethodPut:
			h.setStatus(w, r)
		default:
			errMethodNotSupported(w, r.Method)
		}
	case "/settings":
		switch r.Method {
		case http.MethodGet:
			h.getSettings(w)
		case http.MethodPut:
			h.patchSettings(w, r)
		default:
			errMethodNotSupported(w, r.Method)
		}
	default:
		errRouteNotSupported(w, r.RequestURI)
	}
}

func (h *vpnHandler) getStatus(w http.ResponseWriter) {
	status := h.looper.GetStatus()
	encoder := json.NewEncoder(w)
	data := statusWrapper{Status: string(status)}
	if err := encoder.Encode(data); err != nil {
		h.warner.Warn(err.Error())
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
}

func (h *vpnHandler) setStatus(w http.ResponseWriter, r *http.Request) {
	decoder := json.NewDecoder(r.Body)
	var data statusWrapper
	if err := decoder.Decode(&data); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	status, err := data.getStatus()
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	outcome, err := h.looper.ApplyStatus(h.ctx, status)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	encoder := json.NewEncoder(w)
	if err := encoder.Encode(outcomeWrapper{Outcome: outcome}); err != nil {
		h.warner.Warn(err.Error())
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
}

func (h *vpnHandler) getSettings(w http.ResponseWriter) {
	settings := h.looper.GetSettings() // already copied
	redactPureVPNSecrets(&settings)
	encoder := json.NewEncoder(w)
	if err := encoder.Encode(settings); err != nil {
		h.warner.Warn(err.Error())
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
}

func (h *vpnHandler) patchSettings(w http.ResponseWriter, r *http.Request) {
	var overrideSettings settings.VPN
	decoder := json.NewDecoder(r.Body)
	err := decoder.Decode(&overrideSettings)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	err = r.Body.Close()
	if err != nil {
		h.warner.Warn("closing body: " + err.Error())
	}

	ignoreRedactedPureVPNSecrets(&overrideSettings)
	updatedSettings := h.looper.GetSettings() // already copied
	updatedSettings.OverrideWith(overrideSettings)
	err = updatedSettings.Validate(h.storage, h.ipv6Supported, h.warner)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	outcome := h.looper.SetSettings(h.ctx, updatedSettings)
	_, err = w.Write([]byte(outcome))
	if err != nil {
		h.warner.Warn("writing response: " + err.Error())
	}
}

// redactedSecret replaces the PureVPN secrets in the settings returned,
// and is ignored when received in settings to update, so a client can
// send back the settings it received without changing the secrets.
const redactedSecret = "[redacted]"

func pureVPNSecrets(vpnSettings *settings.VPN) [3]**string {
	return [...]**string{
		&vpnSettings.PureVPN.Password,
		&vpnSettings.PureVPN.TOTPSecret,
		&vpnSettings.PureVPN.SessionToken,
	}
}

// redactPureVPNSecrets replaces each PureVPN secret set with the
// redacted placeholder. The settings given must be a copy, since
// the secret pointers are replaced.
func redactPureVPNSecrets(vpnSettings *settings.VPN) {
	for _, secret := range pureVPNSecrets(vpnSettings) {
		if *secret != nil && **secret != "" {
			*secret = new(redactedSecret)
		}
	}
}

// ignoreRedactedPureVPNSecrets unsets each PureVPN secret set to the
// redacted placeholder, so the current secret is kept.
func ignoreRedactedPureVPNSecrets(vpnSettings *settings.VPN) {
	for _, secret := range pureVPNSecrets(vpnSettings) {
		if *secret != nil && **secret == redactedSecret {
			*secret = nil
		}
	}
}
