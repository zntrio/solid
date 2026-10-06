// Licensed to SolID under one or more contributor
// license agreements. See the NOTICE file distributed with
// this work for additional information regarding copyright
// ownership. SolID licenses this file to you under
// the Apache License, Version 2.0 (the "License"); you may
// not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations
// under the License.

package cwt

import (
	"context"
	"crypto"
	"crypto/rand"
	_ "crypto/sha256" // ECDSA hash functions required by go-cose verifiers
	_ "crypto/sha512"
	"encoding/base64"
	"errors"
	"fmt"

	cbor "github.com/fxamacker/cbor/v2"
	jwxjwk "github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/veraison/go-cose"

	"zntr.io/solid/sdk/jwk"
	"zntr.io/solid/sdk/token"
	"zntr.io/solid/sdk/types"
)

// contentTypeCWT is the ContentType of the CWT serializer and verifiers,
// paired with token.HeaderType to derive typ header values.
const contentTypeCWT = "CWT"

// DefaultSigner declares a default CWT signer producing COSE_Sign1 (tag 18)
// objects as defined by RFC 8392 section 7.1, on the algorithm allowlist
// enforced below (elliptic curves only).
func DefaultSigner(tokenType string, alg cose.Algorithm, keyProvider jwk.KeyProviderFunc) token.Signer {
	return &defaultSigner{
		tokenType:   tokenType,
		alg:         alg,
		keyProvider: keyProvider,
	}
}

// -----------------------------------------------------------------------------

type defaultSigner struct {
	tokenType   string
	alg         cose.Algorithm
	keyProvider jwk.KeyProviderFunc
}

func (ds *defaultSigner) Sign(ctx context.Context, claims any) (string, error) {
	// Check arguments
	if types.IsNil(claims) {
		return "", errors.New("unable to sign nil claim object")
	}
	if ds.keyProvider == nil {
		return "", errors.New("unable to use nil keyProvider")
	}

	// Resolve and materialize the signing key as a crypto.Signer
	// consumable by go-cose.
	keySigner, kid, err := ResolveSigningKey(ctx, ds.keyProvider)
	if err != nil {
		return "", err
	}

	// Enforce the algorithm allowlist: elliptic curves only, no RSA / HS
	// families (project security posture).
	if errAlg := EnforceAlgorithmAllowlist(ds.alg); errAlg != nil {
		return "", errAlg
	}

	// Prepare signer. ML-DSA keys (AKP) are signed through the external
	// RFC 9964 signer; every other algorithm goes through the go-cose
	// constructor on the materialized crypto.Signer.
	var signer cose.Signer
	if akp, isAKP := keySigner.(*jwk.MLDSAKey); isAKP {
		signer, err = CoseSignerMLDSAForKey(akp)
		if err != nil {
			return "", err
		}
	} else {
		cryptoSigner, isCryptoSigner := keySigner.(crypto.Signer)
		if !isCryptoSigner {
			return "", fmt.Errorf("unable to materialize signing key: unsupported key type %T", keySigner)
		}
		signer, err = cose.NewSigner(ds.alg, cryptoSigner)
		if err != nil {
			return "", fmt.Errorf("unable to initialize COSE signer: %w", err)
		}
	}

	// All header parameters are protected (RFC 8392 follows the COSE
	// signing defaults): kid as a bstr per RFC 9052 section 3.1, typ in
	// the RFC 8725 section 3.11 explicit media-type form required by
	// go-cose header validation.
	headers := cose.Headers{
		Protected: cose.ProtectedHeader{
			cose.HeaderLabelAlgorithm: ds.alg,
			cose.HeaderLabelKeyID:     []byte(kid),
			cose.HeaderLabelType:      token.HeaderType(ds.tokenType, contentTypeCWT),
		},
		Unprotected: cose.UnprotectedHeader{},
	}

	// Prepare claims
	payload, err := cbor.Marshal(claims)
	if err != nil {
		return "", fmt.Errorf("unable to serialize claims as CBOR: %w", err)
	}

	// Assemble final assertion
	msg := cose.Sign1Message{
		Headers: headers,
		Payload: payload,
	}

	// Sign assertion (no external AAD)
	if err = msg.Sign(rand.Reader, nil, signer); err != nil {
		return "", fmt.Errorf("unable to sign claims: %w", err)
	}

	// Marshal final assertion
	assertion, err := msg.MarshalCBOR()
	if err != nil {
		return "", fmt.Errorf("unable to marshal assertion: %w", err)
	}

	// No error
	return base64.RawURLEncoding.EncodeToString(assertion), nil
}

func (ds *defaultSigner) ContentType() string {
	return contentTypeCWT
}

// supportedSignAlgorithms is the COSE signing algorithm allowlist for the
// CWT serializer: elliptic curves and ML-DSA only, no RSA / HS families
// (project security posture), mirroring the JOSE allowlist.
var supportedSignAlgorithms = []cose.Algorithm{
	cose.AlgorithmES256,
	cose.AlgorithmES384,
	cose.AlgorithmES512,
	AlgorithmMLDSA44,
	AlgorithmMLDSA65,
	AlgorithmMLDSA87,
}

// EnforceAlgorithmAllowlist rejects any signing algorithm outside the
// supported elliptic-curve / ML-DSA set.
func EnforceAlgorithmAllowlist(alg cose.Algorithm) error {
	for _, supported := range supportedSignAlgorithms {
		if alg == supported {
			return nil
		}
	}
	return fmt.Errorf("unsupported COSE algorithm %q", alg.String())
}

// ResolveSigningKey invokes the key provider and returns the signing key.
// AKP keys (ML-DSA, RFC 9964) are returned as-is: the caller routes them
// to the external cose.Signer implementation, since go-cose does not
// know the algorithm. Every other key type is materialized as a native
// crypto.Signer consumable by the go-cose constructors.
func ResolveSigningKey(ctx context.Context, keyProvider jwk.KeyProviderFunc) (signingKey any, keyID string, err error) {
	// Retrieve signing key
	key, err := keyProvider(ctx)
	if err != nil {
		return nil, "", fmt.Errorf("unable to retrieve a signing key: %w", err)
	}

	// Check
	if key == nil {
		return nil, "", fmt.Errorf("key provider returned a nil key")
	}
	kid, ok := key.KeyID()
	if !ok || kid == "" {
		return nil, "", fmt.Errorf("key provider returned a unidentifiable key")
	}

	// AKP keys bypass the jwx private-key check (jwx does not know the
	// key type); their own constructor guarantees private material.
	if akp, isAKP := key.(*jwk.MLDSAKey); isAKP {
		if akp.PrivateKey() == nil {
			return nil, "", fmt.Errorf("key provider returned a public key which is unusable for signing purpose")
		}
		return akp, kid, nil
	}

	isPrivate, err := jwxjwk.IsPrivateKey(key)
	if err != nil || !isPrivate {
		return nil, "", fmt.Errorf("key provider returned a public key which is unusable for signing purpose")
	}

	// Materialize the raw key for COSE.
	var keyRaw any
	if err = jwxjwk.Export(key, &keyRaw); err != nil {
		return nil, "", fmt.Errorf("unable to materialize signing key: %w", err)
	}
	keySigner, isCryptoSigner := keyRaw.(crypto.Signer)
	if !isCryptoSigner {
		return nil, "", fmt.Errorf("unable to materialize signing key: unsupported key type %T", keyRaw)
	}

	return keySigner, kid, nil
}
