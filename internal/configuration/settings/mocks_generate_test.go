package settings

//go:generate mockgen -destination=mocks_test.go -package=$GOPACKAGE . FilterChoicesGetter,Warner
//go:generate mockgen -destination=mocks_reader_test.go -package=$GOPACKAGE github.com/qdm12/gosettings/reader Source
