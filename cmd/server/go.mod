module zntr.io/solid/cmd/server

replace zntr.io/solid => ../../

replace github.com/kr/session => github.com/Zenithar/session v0.1.1-0.20200929071535-c4de738d3339

go 1.17

require (
	github.com/dchest/uniuri v0.0.0-20200228104902-7aecb25e1fe5
	github.com/json-iterator/go v1.1.12
	go.mozilla.org/cose v0.0.0-20200930124131-25dc96df8228
	google.golang.org/protobuf v1.27.1
	gopkg.in/square/go-jose.v2 v2.6.0
	zntr.io/solid v0.0.0-00010101000000-000000000000
)

require (
	github.com/asaskevich/govalidator v0.0.0-20200108200545-475eaeb16496 // indirect
	github.com/fxamacker/cbor/v2 v2.3.0 // indirect
	github.com/go-ozzo/ozzo-validation/v4 v4.3.0 // indirect
	github.com/modern-go/concurrent v0.0.0-20180228061459-e0a39a4cb421 // indirect
	github.com/modern-go/reflect2 v1.0.2 // indirect
	github.com/patrickmn/go-cache v2.1.0+incompatible // indirect
	github.com/pkg/errors v0.8.1 // indirect
	github.com/x448/float16 v0.8.4 // indirect
	golang.org/x/crypto v0.0.0-20210921155107-089bfa567519 // indirect
	golang.org/x/sys v0.0.0-20211025201205-69cdffdb9359 // indirect
)
