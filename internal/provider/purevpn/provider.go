package purevpn

import (
	"github.com/qdm12/gluetun/internal/constants/providers"
	"github.com/qdm12/gluetun/internal/provider/common"
	"github.com/qdm12/gluetun/internal/provider/purevpn/updater"
	"github.com/qdm12/gluetun/internal/provider/utils"
)

type Provider struct {
	storage    common.Storage
	connPicker *utils.ConnectionPicker
	wireguard  *wireguardFetcher
	common.Fetcher
}

func New(storage common.Storage, ipFetcher common.IPFetcher, unzipper common.Unzipper,
	updaterWarner common.Warner, parallelResolver common.ParallelResolver,
	restrictedNet RestrictedNetwork,
) *Provider {
	return &Provider{
		storage:    storage,
		connPicker: utils.NewConnectionPicker(),
		wireguard:  newWireguardFetcher(restrictedNet),
		Fetcher:    updater.New(ipFetcher, unzipper, updaterWarner, parallelResolver),
	}
}

func (p *Provider) Name() string {
	return providers.Purevpn
}
