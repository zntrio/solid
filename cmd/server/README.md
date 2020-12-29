# Sample HTTP Server

## Generate `client_assertion`

```sh
export JWT_ASSERTION=$(go run ../assertionbuilder/main.go)
```

It will generate a JWT Token, signed with tthe bundled private key, this token
will be sent to the AS as a `client_assertion` to be verified using registered
client public key.

> Proof of possession should be added to proof private key ownership.

## Protocol

### Authorization Code (Online User)

Client:

Registers a new authorization request using its client credentials.

> No authorization fliw could be started without this initial client
> authentication. The client have to complete control of the authorization
> request.

```sh
$ curl -XPOST http://127.0.0.1:8080/par\?state\=1234\&scope\=openid%20email\&response_type\=code\&client_id\=6779ef20e75817b79602\&redirect_uri\=http%3A%2F%2Flocalhost%3A8080%2Fcb\&code_challenge\=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM\&code_challenge_method\=S256\&
client_assertion_type\=urn%3Aietf%3Aparams%3Aoauth%3Aclient-assertion-type%3Ajwt-bearer\&client_assertion\=$JWT_ASSERTION
{"request_uri":"urn:solid:rhK3Ys6mdLDcJxus","expires_in":90}
```

Send the response back to user agent.

User Agent:

> Pushed Authorization Requests remove authorization requests from user agent
> so that it reduces the threats from user_agent to only accessible threats
> from the redirect_uri parameter.

Redirected to AS, User must identify himself using authentication method.
He has to send the `request_uri` to continue the `authorization_code` flow
without the knowledge of initial authorization request parameters.

```sh
$ curl http://127.0.0.1:8080/authorize\?\request_uri\=urn%3Asolid%3ArhK3Ys6mdLDcJxus
{"code":"9xrSQZIzfMmsTHco","state":"1234"}
```

Client:

Once AS redirected back to client, you have to exchange the authorization code
receive as you do in a normal `authorization_code` flow.

```sh
$ curl http://127.0.0.1:8080/token\?grant_type\=authorization_code\&redirect_uri\=http%3A%2F%2Flocalhost%3A8080%2Fcb\&code_verifier\=dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk\&
client_assertion_type\=urn%3Aietf%3Aparams%3Aoauth%3Aclient-assertion-type%3Ajwt-bearer\&client_assertion\=$JWT_ASSERTION
\&code\=9xrSQZIzfMmsTHco
{"access_token":"MqW.It14pATfNVoLimuiH8W0b7W54oFAjfcB2D8J7zHh5NCs8zZfsIaETVXGaDxO","token_type":"Bearer","expires_in":3600}
```

## Client Credentials (Machine-to-Machine)

Client:

```sh
$ curl http://127.0.0.1:8080/token\?grant_type\=client_credentials\&
client_assertion_type\=urn%3Aietf%3Aparams%3Aoauth%3Aclient-assertion-type%3Ajwt-bearer\&client_assertion\=$JWT_ASSERTION
{"access_token":"MqW.It14pATfNVoLimuiH8W0b7W54oFAjfcB2D8J7zHh5NCs8zZfsIaETVXGaDxO","token_type":"Bearer","expires_in":3600}
```
