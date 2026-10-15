package vpn

//go:generate mockgen -destination=mocks_test.go -package=$GOPACKAGE . Firewall,WireguardFetcher
//go:generate mockgen -destination=mocks_wireguard_test.go -package=$GOPACKAGE github.com/qdm12/gluetun/internal/wireguard Logger
