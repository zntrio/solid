module zntr.io/solid/cmd/server

replace zntr.io/solid => ../../

go 1.15

require (
	github.com/dchest/uniuri v0.0.0-20200228104902-7aecb25e1fe5
	github.com/golang/protobuf v1.4.3
	github.com/imdario/mergo v0.3.11
	github.com/json-iterator/go v1.1.10
	github.com/square/go-jose/v3 v3.0.0-20200630053402-0a67ce9b0693
	go.mozilla.org/cose v0.0.0-20200930124131-25dc96df8228
	google.golang.org/protobuf v1.25.0
	zntr.io/solid v0.0.0-00010101000000-000000000000
)
