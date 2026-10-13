// Command coapace demonstrates OAuth 2.0 over CoAP per RFC 9200
// (ACE-OAuth): a client obtains a certificate-bound access token from
// an in-process authorization server and presents it to a CoAP resource
// server over DTLS 1.3 (pion/dtls), with the wire codec from sdk/ace.
//
// This demo lives in its own Go module: the CoAP/DTLS transport stack
// (plgd-dev/go-coap, pion/dtls) is presentation-layer tooling that must
// stay out of the core zntr.io/solid dependency graph, which remains
// transport-agnostic.
module zntr.io/solid/examples/coapace

go 1.27.2

replace zntr.io/solid => ../../

require (
	github.com/lestrrat-go/jwx/v3 v3.3.0
	github.com/pion/dtls/v3 v3.1.10
	github.com/plgd-dev/go-coap/v3 v3.5.4
	github.com/veraison/go-cose v1.3.0
	zntr.io/solid v0.0.0-00010101000000-000000000000
)

require (
	buf.build/gen/go/bufbuild/protovalidate/protocolbuffers/go v1.36.12-20260825204119-511051f7f437.2 // indirect
	buf.build/go/protovalidate v1.4.0 // indirect
	cel.dev/cel-go v0.32.0 // indirect
	cel.dev/expr v0.25.3 // indirect
	github.com/antlr4-go/antlr/v4 v4.13.1 // indirect
	github.com/decred/dcrd/dcrec/secp256k1/v4 v4.4.1 // indirect
	github.com/dsnet/golib/memfile v1.0.0 // indirect
	github.com/fxamacker/cbor/v2 v2.9.4 // indirect
	github.com/goccy/go-json v0.10.6 // indirect
	github.com/golang-jwt/jwt/v5 v5.3.1 // indirect
	github.com/lestrrat-go/blackmagic v1.0.4 // indirect
	github.com/lestrrat-go/httpcc v1.0.1 // indirect
	github.com/lestrrat-go/httprc/v3 v3.0.6 // indirect
	github.com/lestrrat-go/option/v2 v2.0.0 // indirect
	github.com/pion/logging v0.2.4 // indirect
	github.com/pion/transport/v5 v5.0.0 // indirect
	github.com/planetscale/vtprotobuf v0.6.1-0.20240319094008-0393e58bdf10 // indirect
	github.com/segmentio/asm v1.2.1 // indirect
	github.com/valyala/fastjson v1.6.10 // indirect
	github.com/x448/float16 v0.8.4 // indirect
	go.uber.org/atomic v1.11.0 // indirect
	go.yaml.in/yaml/v3 v3.0.5 // indirect
	golang.org/x/crypto v0.58.0 // indirect
	golang.org/x/exp v0.0.0-20260820142414-ca536658362e // indirect
	golang.org/x/net v0.61.0 // indirect
	golang.org/x/sync v0.24.0 // indirect
	golang.org/x/sys v0.49.0 // indirect
	golang.org/x/text v0.43.0 // indirect
	google.golang.org/genproto/googleapis/api v0.0.0-20260819154853-08b0e4226688 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20260819154853-08b0e4226688 // indirect
	google.golang.org/grpc v1.86.0-dev // indirect
	google.golang.org/protobuf v1.36.12 // indirect
)
