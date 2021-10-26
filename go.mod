module zntr.io/solid

go 1.17

replace github.com/kr/session => github.com/Zenithar/session v0.1.1-0.20200929071535-c4de738d3339

// Nancy findings
replace github.com/gogo/protobuf => github.com/gogo/protobuf v1.3.2

require (
	github.com/Masterminds/semver/v3 v3.1.1
	github.com/dchest/uniuri v0.0.0-20200228104902-7aecb25e1fe5
	github.com/fatih/color v1.13.0
	github.com/fxamacker/cbor/v2 v2.3.0
	github.com/go-ozzo/ozzo-validation/v4 v4.3.0
	github.com/golang/mock v1.6.0
	github.com/golang/protobuf v1.5.2
	github.com/google/go-cmp v0.5.6
	github.com/google/gofuzz v1.2.0
	github.com/iancoleman/strcase v0.2.0
	github.com/kr/session v0.0.0-00010101000000-000000000000
	github.com/magefile/mage v1.11.0
	github.com/o1egl/paseto v1.0.0
	github.com/patrickmn/go-cache v2.1.0+incompatible
	github.com/spf13/cobra v1.2.1
	go.mozilla.org/cose v0.0.0-20200930124131-25dc96df8228
	golang.org/x/crypto v0.0.0-20210921155107-089bfa567519
	golang.org/x/oauth2 v0.0.0-20211005180243-6b3c2da341f1
	golang.org/x/sys v0.0.0-20211025201205-69cdffdb9359
	google.golang.org/protobuf v1.27.1
	gopkg.in/square/go-jose.v2 v2.6.0
)

require (
	github.com/aead/chacha20 v0.0.0-20180709150244-8b13a72661da // indirect
	github.com/aead/chacha20poly1305 v0.0.0-20170617001512-233f39982aeb // indirect
	github.com/aead/poly1305 v0.0.0-20180717145839-3fee0db0b635 // indirect
	github.com/asaskevich/govalidator v0.0.0-20200108200545-475eaeb16496 // indirect
	github.com/inconshreveable/mousetrap v1.0.0 // indirect
	github.com/mattn/go-colorable v0.1.9 // indirect
	github.com/mattn/go-isatty v0.0.14 // indirect
	github.com/pkg/errors v0.8.1 // indirect
	github.com/spf13/pflag v1.0.5 // indirect
	github.com/x448/float16 v0.8.4 // indirect
	golang.org/x/net v0.0.0-20210405180319-a5a99cb37ef4 // indirect
	golang.org/x/xerrors v0.0.0-20200804184101-5ec99f83aff1 // indirect
	google.golang.org/appengine v1.6.7 // indirect
)
