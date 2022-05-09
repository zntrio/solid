package main

import (
	"log"
	"net/http"

	"gopkg.in/square/go-jose.v2"

	"zntr.io/solid/examples/server/handlers"
	"zntr.io/solid/examples/server/middleware"
	"zntr.io/solid/sdk/dpop"
	"zntr.io/solid/sdk/generator"
	"zntr.io/solid/sdk/jarm"
	"zntr.io/solid/sdk/pairwise"
	sdktoken "zntr.io/solid/sdk/token"
	"zntr.io/solid/sdk/token/jwt"
	"zntr.io/solid/server/services/authorization"
	"zntr.io/solid/server/services/device"
	"zntr.io/solid/server/services/token"
	"zntr.io/solid/server/storage/inmemory"
)

func main() {
	// Generators
	authorizationCodes := generator.DefaultAuthorizationCode()
	requestURIs := generator.DefaultRequestURI()
	deviceCodes := generator.DefaultDeviceCode()
	deviceUserCodes := generator.DefaultDeviceUserCode()

	// Create storage
	clients := inmemory.Clients()
	tokens := inmemory.Tokens()
	resources := inmemory.Resources()
	proofs := inmemory.DPoPProofs()
	authRequests := inmemory.AuthorizationRequests()
	authSessions := inmemory.AuthorizationCodeSessions()
	deviceSessions := inmemory.DeviceCodeSessions()

	// Token generator
	accessTokens := sdktoken.OpaqueToken()
	refreshTokens := sdktoken.OpaqueToken()

	// Prepare services
	authz := authorization.New(clients, authRequests, authSessions, authorizationCodes, requestURIs)
	tokenz := token.New(accessTokens, refreshTokens, clients, authRequests, authSessions, deviceSessions, tokens, resources)
	devicez := device.New(clients, deviceSessions, deviceCodes, deviceUserCodes)

	// Middlewares
	secHeaders := middleware.SecurityHaders()
	basicAuth := middleware.BasicAuthentication()
	clientAuth := middleware.ClientAuthentication(clients)

	// Request encoders
	keys := keyProvider()
	keySet := keySetProvider()
	jarmEncoder := jarm.Encoder(jwt.JARMSigner(jose.ES384, keys))
	dpopVerifier := dpop.DefaultVerifier(proofs, jwt.DefaultVerifier(keySet, []string{"ES384"}))
	pairwiseEncoder := pairwise.Hash([]byte("U|(vBPu45_Vkvv*Tr*8Y[^s?,$ka@bQziM5]9.+[{.n47]'zokA7-j8ypJ=W]WS"))
	issuer := "http://127.0.0.1:8080"

	// Create router
	http.Handle("/.well-known/oauth-authorization-server", handlers.Metadata(issuer, jwt.ServerMetadata(jose.ES384, keys)))
	http.Handle("/.well-known/openid-configuration", handlers.Metadata(issuer, jwt.ServerMetadata(jose.ES384, keys)))
	http.Handle("/keys", handlers.JWKS(keySet))
	http.Handle("/par", middleware.Adapt(handlers.PushedAuthorizationRequest(issuer, authz, dpopVerifier), clientAuth))
	http.Handle("/authorize", middleware.Adapt(handlers.Authorization(issuer, authz, clients, jarmEncoder, pairwiseEncoder), secHeaders, basicAuth))
	http.Handle("/token", middleware.Adapt(handlers.Token(issuer, tokenz, dpopVerifier), clientAuth))
	http.Handle("/token/introspect", middleware.Adapt(handlers.TokenIntrospection(issuer, tokenz), clientAuth))
	http.Handle("/token/revoke", middleware.Adapt(handlers.TokenRevocation(issuer, tokenz), clientAuth))
	http.Handle("/device/authorize", middleware.Adapt(handlers.DeviceAuthorization(issuer, devicez), clientAuth))
	http.Handle("/device", middleware.Adapt(handlers.Device(issuer, devicez), secHeaders, basicAuth))

	log.Fatal(http.ListenAndServe(":8080", nil))
}
