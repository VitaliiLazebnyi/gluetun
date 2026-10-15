package vpn

//go:generate mockgen -destination=mocks_local_test.go -package $GOPACKAGE -source interfaces_local.go
//go:generate mockgen -destination=mocks_test.go -package $GOPACKAGE . Firewall
//go:generate mockgen -destination=mocks_provider_test.go -package $GOPACKAGE github.com/qdm12/gluetun/internal/provider Provider
//go:generate mockgen -destination=mocks_wireguard_test.go -package $GOPACKAGE github.com/qdm12/gluetun/internal/wireguard Logger
