package purevpn

//go:generate mockgen -destination=mocks_test.go -package=$GOPACKAGE . Logger
//go:generate mockgen -destination=mocks_wireguard_test.go -package=$GOPACKAGE -mock_names=Logger=MockWireguardLogger github.com/qdm12/gluetun/internal/wireguard Logger
