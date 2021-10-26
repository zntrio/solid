module zntr.io/solid/cmd/server

replace zntr.io/solid => ../../

replace github.com/kr/session => github.com/Zenithar/session v0.1.1-0.20200929071535-c4de738d3339

go 1.16

require (
	github.com/dchest/uniuri v0.0.0-20200228104902-7aecb25e1fe5
	github.com/golang/protobuf v1.5.2 // indirect
	github.com/imdario/mergo v0.3.12 // indirect
	github.com/json-iterator/go v1.1.11
	go.mozilla.org/cose v0.0.0-20200930124131-25dc96df8228
	google.golang.org/protobuf v1.26.0
	gopkg.in/square/go-jose.v2 v2.5.1
	zntr.io/solid v0.0.0-00010101000000-000000000000
)
