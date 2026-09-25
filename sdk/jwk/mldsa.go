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

package jwk

import (
	"crypto"
	"crypto/mldsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"sync"

	golangjwt "github.com/golang-jwt/jwt/v5"
	"github.com/lestrrat-go/jwx/v3/cert"
	"github.com/lestrrat-go/jwx/v3/jwa"
	jwxjwk "github.com/lestrrat-go/jwx/v3/jwk"
)

// ML-DSA signing methods (FIPS 204), as specified by the draft
// "ML-DSA for JOSE and COSE" (draft-ietf-cose-dilithium).
//
// Signing requires a *mldsa.PrivateKey, verification a *mldsa.PublicKey,
// passed directly to the golang-jwt signing calls (SignedString / Parse
// keyfunc / SigningMethod.Verify).
//
// The JWK representation of ML-DSA keys (kty "AKP", member "pub" holding
// the raw NIST public key bytes, per draft-ietf-cose-dilithium) is
// provided by MLDSAKey, which implements the Key interface. jwx v3 does
// not support the AKP key type natively.
const (
	// MLDSA44 is the ML-DSA-44 signature algorithm.
	MLDSA44 = "ML-DSA-44"
	// MLDSA65 is the ML-DSA-65 signature algorithm.
	MLDSA65 = "ML-DSA-65"
	// MLDSA87 is the ML-DSA-87 signature algorithm.
	MLDSA87 = "ML-DSA-87"
	// akpKty is the draft-ietf-cose-dilithium JWK key type of ML-DSA keys.
	akpKty = "AKP"
)

var (
	// SigningMethodMLDSA44 is the ML-DSA-44 signing method for golang-jwt.
	SigningMethodMLDSA44 golangjwt.SigningMethod = &signingMethodMLDSA{alg: MLDSA44}
	// SigningMethodMLDSA65 is the ML-DSA-65 signing method for golang-jwt.
	SigningMethodMLDSA65 golangjwt.SigningMethod = &signingMethodMLDSA{alg: MLDSA65}
	// SigningMethodMLDSA87 is the ML-DSA-87 signing method for golang-jwt.
	SigningMethodMLDSA87 golangjwt.SigningMethod = &signingMethodMLDSA{alg: MLDSA87}
)

func init() {
	// Register the ML-DSA algorithm names with jwa so jwa.KeyAlgorithmFrom
	// resolves them (used by jwk.Key.Algorithm consumers).
	jwa.RegisterSignatureAlgorithm(
		jwa.NewSignatureAlgorithm(MLDSA44),
		jwa.NewSignatureAlgorithm(MLDSA65),
		jwa.NewSignatureAlgorithm(MLDSA87),
	)
	golangjwt.RegisterSigningMethod(MLDSA44, func() golangjwt.SigningMethod { return SigningMethodMLDSA44 })
	golangjwt.RegisterSigningMethod(MLDSA65, func() golangjwt.SigningMethod { return SigningMethodMLDSA65 })
	golangjwt.RegisterSigningMethod(MLDSA87, func() golangjwt.SigningMethod { return SigningMethodMLDSA87 })
}

type signingMethodMLDSA struct {
	alg string
}

// Alg implements the golangjwt.SigningMethod interface.
func (m *signingMethodMLDSA) Alg() string {
	return m.alg
}

// Sign implements the golangjwt.SigningMethod interface. The key must be a
// *mldsa.PrivateKey.
func (m *signingMethodMLDSA) Sign(signingString string, key any) ([]byte, error) {
	priv, ok := key.(*mldsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("ML-DSA signing requires a *mldsa.PrivateKey, got %T", key)
	}
	return priv.Sign(nil, []byte(signingString), crypto.Hash(0))
}

// Verify implements the golangjwt.SigningMethod interface. The key must be a
// *mldsa.PublicKey.
func (m *signingMethodMLDSA) Verify(signingString string, signature []byte, key any) error {
	pub, ok := key.(*mldsa.PublicKey)
	if !ok {
		return fmt.Errorf("ML-DSA verification requires a *mldsa.PublicKey, got %T", key)
	}
	return mldsa.Verify(pub, []byte(signingString), signature, nil)
}

// -----------------------------------------------------------------------------

var _ Key = (*MLDSAKey)(nil)

// MLDSAKey is a JWK representation of an ML-DSA key pair (kty "AKP",
// draft-ietf-cose-dilithium). The public key bytes are carried in the
// "pub" member; the private key is held as the raw Go key, never
// serialized.
type MLDSAKey struct {
	mu     sync.RWMutex
	params mldsa.Parameters
	priv   *mldsa.PrivateKey
	pub    *mldsa.PublicKey

	kty string
	kid string
	alg string
	use string
}

// NewMLDSAKey wraps an ML-DSA private key as a JWK-compatible key.
func NewMLDSAKey(priv *mldsa.PrivateKey) (*MLDSAKey, error) {
	if priv == nil {
		return nil, errors.New("unable to wrap nil ML-DSA private key")
	}

	pub := priv.PublicKey()
	if pub == nil {
		return nil, errors.New("unable to derive ML-DSA public key")
	}

	return &MLDSAKey{
		params: pub.Parameters(),
		priv:   priv,
		pub:    pub,
		kty:    akpKty,
		alg:    mldsaAlgName(pub.Parameters()),
	}, nil
}

// NewMLDSAKeyFromPublic wraps an ML-DSA public key as a JWK-compatible key.
func NewMLDSAKeyFromPublic(pub *mldsa.PublicKey) (*MLDSAKey, error) {
	if pub == nil {
		return nil, errors.New("unable to wrap nil ML-DSA public key")
	}

	return &MLDSAKey{
		params: pub.Parameters(),
		pub:    pub,
		kty:    akpKty,
		alg:    mldsaAlgName(pub.Parameters()),
	}, nil
}

// PrivateKey returns the wrapped ML-DSA private key, or nil when the key
// only holds public material.
func (k *MLDSAKey) PrivateKey() *mldsa.PrivateKey {
	return k.priv
}

// MLDSPublicKey returns the wrapped raw ML-DSA public key.
func (k *MLDSAKey) MLDSPublicKey() *mldsa.PublicKey {
	return k.pub
}

func mldsaAlgName(params mldsa.Parameters) string {
	switch params.String() {
	case "ML-DSA-44":
		return MLDSA44
	case "ML-DSA-65":
		return MLDSA65
	case "ML-DSA-87":
		return MLDSA87
	default:
		return params.String()
	}
}

// KeyType implements the Key interface.
func (k *MLDSAKey) KeyType() jwa.KeyType {
	return jwa.NewKeyType(akpKty)
}

// KeyUsage implements the Key interface.
func (k *MLDSAKey) KeyUsage() (string, bool) { return k.use, k.use != "" }

// KeyOps implements the Key interface.
func (k *MLDSAKey) KeyOps() (jwxjwk.KeyOperationList, bool) { return nil, false }

// Algorithm implements the Key interface.
func (k *MLDSAKey) Algorithm() (jwa.KeyAlgorithm, bool) {
	alg, err := jwa.KeyAlgorithmFrom(k.alg)
	if err != nil {
		return nil, false
	}
	return alg, true
}

// KeyID implements the Key interface.
func (k *MLDSAKey) KeyID() (string, bool) { return k.kid, k.kid != "" }

// X509URL implements the Key interface.
func (k *MLDSAKey) X509URL() (string, bool) { return "", false }

// X509CertChain implements the Key interface.
func (k *MLDSAKey) X509CertChain() (*cert.Chain, bool) { return nil, false }

// X509CertThumbprint implements the Key interface.
func (k *MLDSAKey) X509CertThumbprint() (string, bool) { return "", false }

// X509CertThumbprintS256 implements the Key interface.
func (k *MLDSAKey) X509CertThumbprintS256() (string, bool) { return "", false }

// Has implements the Key interface.
func (k *MLDSAKey) Has(name string) bool {
	k.mu.RLock()
	defer k.mu.RUnlock()

	switch name {
	case jwxjwk.KeyTypeKey:
		return true
	case jwxjwk.AlgorithmKey:
		return k.alg != ""
	case jwxjwk.KeyIDKey:
		return k.kid != ""
	case jwxjwk.KeyUsageKey:
		return k.use != ""
	case "pub":
		return k.pub != nil
	default:
		return false
	}
}

// Keys implements the Key interface.
func (k *MLDSAKey) Keys() []string {
	k.mu.RLock()
	defer k.mu.RUnlock()

	keys := []string{jwxjwk.KeyTypeKey, "pub"}
	if k.alg != "" {
		keys = append(keys, jwxjwk.AlgorithmKey)
	}
	if k.kid != "" {
		keys = append(keys, jwxjwk.KeyIDKey)
	}
	if k.use != "" {
		keys = append(keys, jwxjwk.KeyUsageKey)
	}
	return keys
}

// Get implements the Key interface.
func (k *MLDSAKey) Get(name string, dst any) error {
	k.mu.RLock()
	defer k.mu.RUnlock()

	switch name {
	case jwxjwk.KeyTypeKey:
		return assign(dst, jwa.NewKeyType(akpKty))
	case jwxjwk.AlgorithmKey:
		if k.alg == "" {
			return fmt.Errorf("field %q not found", name)
		}
		alg, err := jwa.KeyAlgorithmFrom(k.alg)
		if err != nil {
			return fmt.Errorf("field %q not found", name)
		}
		return assign(dst, alg)
	case jwxjwk.KeyIDKey:
		if k.kid == "" {
			return fmt.Errorf("field %q not found", name)
		}
		return assign(dst, k.kid)
	case jwxjwk.KeyUsageKey:
		if k.use == "" {
			return fmt.Errorf("field %q not found", name)
		}
		return assign(dst, k.use)
	case "pub":
		if k.pub == nil {
			return fmt.Errorf("field %q not found", name)
		}
		return assign(dst, k.pub.Bytes())
	default:
		return fmt.Errorf("field %q not found", name)
	}
}

// Set implements the Key interface. Supported fields: kid, use, alg.
func (k *MLDSAKey) Set(name string, value any) error {
	k.mu.Lock()
	defer k.mu.Unlock()

	switch name {
	case jwxjwk.KeyIDKey:
		s, ok := value.(string)
		if !ok {
			return fmt.Errorf("invalid value type %T for field %q", value, name)
		}
		k.kid = s
		return nil
	case jwxjwk.KeyUsageKey:
		s, ok := value.(string)
		if !ok {
			return fmt.Errorf("invalid value type %T for field %q", value, name)
		}
		k.use = s
		return nil
	case jwxjwk.AlgorithmKey:
		s, ok := value.(string)
		if !ok {
			return fmt.Errorf("invalid value type %T for field %q", value, name)
		}
		k.alg = s
		return nil
	case jwxjwk.KeyTypeKey:
		// kty is immutable; ignore like jwx does.
		return nil
	default:
		return fmt.Errorf("field %q not found", name)
	}
}

// Remove implements the Key interface.
func (k *MLDSAKey) Remove(name string) error {
	k.mu.Lock()
	defer k.mu.Unlock()

	switch name {
	case jwxjwk.KeyIDKey:
		k.kid = ""
		return nil
	case jwxjwk.KeyUsageKey:
		k.use = ""
		return nil
	case jwxjwk.AlgorithmKey:
		k.alg = mldsaAlgName(k.params)
		return nil
	default:
		return fmt.Errorf("field %q not found", name)
	}
}

// Validate implements the Key interface.
func (k *MLDSAKey) Validate() error {
	if k.pub == nil {
		return errors.New("ML-DSA key has no public key material")
	}
	return nil
}

// Thumbprint implements the Key interface (RFC 7638). The canonical
// JSON for the AKP key type is `{"alg":"...","kty":"AKP","pub":"..."}`
// per draft-ietf-cose-dilithium.
func (k *MLDSAKey) Thumbprint(hash crypto.Hash) ([]byte, error) {
	k.mu.RLock()
	defer k.mu.RUnlock()

	if k.pub == nil {
		return nil, errors.New("ML-DSA key has no public key material")
	}

	pub64 := base64.RawURLEncoding.EncodeToString(k.pub.Bytes())
	canonical := fmt.Sprintf(`{"alg":%q,"kty":"`+akpKty+`","pub":%q}`, k.alg, pub64)
	h := hash.New()
	if _, err := h.Write([]byte(canonical)); err != nil {
		return nil, err
	}
	return h.Sum(nil), nil
}

// PublicKey implements the Key interface: returns a public-only copy.
func (k *MLDSAKey) PublicKey() (Key, error) {
	k.mu.RLock()
	defer k.mu.RUnlock()

	return &MLDSAKey{
		params: k.params,
		pub:    k.pub,
		kty:    k.kty,
		alg:    k.alg,
		use:    k.use,
	}, nil
}

// Clone implements the Key interface.
func (k *MLDSAKey) Clone() (Key, error) {
	k.mu.RLock()
	defer k.mu.RUnlock()

	return &MLDSAKey{
		params: k.params,
		priv:   k.priv,
		pub:    k.pub,
		kty:    k.kty,
		kid:    k.kid,
		alg:    k.alg,
		use:    k.use,
	}, nil
}

// MarshalJSON implements json.Marshaler: emits the AKP JWK form. Private
// material is never serialized.
func (k *MLDSAKey) MarshalJSON() ([]byte, error) {
	k.mu.RLock()
	defer k.mu.RUnlock()

	if k.pub == nil {
		return nil, errors.New("ML-DSA key has no public key material")
	}

	m := map[string]any{
		"kty": akpKty,
		"alg": k.alg,
		"pub": base64.RawURLEncoding.EncodeToString(k.pub.Bytes()),
	}
	if k.kid != "" {
		m["kid"] = k.kid
	}
	if k.use != "" {
		m["use"] = k.use
	}
	return json.Marshal(m)
}

// -----------------------------------------------------------------------------

// akpJWK is the wire form of an AKP JWK (draft-ietf-cose-dilithium).
type akpJWK struct {
	Kty string `json:"kty"`
	Alg string `json:"alg"`
	Kid string `json:"kid"`
	Use string `json:"use"`
	Pub string `json:"pub"`
	D   string `json:"d,omitempty"`
}

// ParseMLDSAJWK parses a single AKP JWK (kty "AKP"). When the private "d"
// member is present it holds the 32-byte seed from which the private key
// is derived; otherwise the key is public-only.
func ParseMLDSAJWK(data []byte) (*MLDSAKey, error) {
	var raw akpJWK
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("unable to parse AKP JWK: %w", err)
	}
	if raw.Kty != akpKty {
		return nil, fmt.Errorf("unexpected key type %q, want AKP", raw.Kty)
	}
	if raw.Pub == "" {
		return nil, fmt.Errorf("AKP JWK has no public key material")
	}

	var params mldsa.Parameters
	switch raw.Alg {
	case MLDSA44:
		params = mldsa.MLDSA44()
	case MLDSA65:
		params = mldsa.MLDSA65()
	case MLDSA87:
		params = mldsa.MLDSA87()
	default:
		return nil, fmt.Errorf("unsupported ML-DSA algorithm %q", raw.Alg)
	}

	pubBytes, err := base64.RawURLEncoding.DecodeString(raw.Pub)
	if err != nil {
		return nil, fmt.Errorf("unable to decode AKP public key: %w", err)
	}
	pub, err := mldsa.NewPublicKey(params, pubBytes)
	if err != nil {
		return nil, fmt.Errorf("unable to build ML-DSA public key: %w", err)
	}

	k := &MLDSAKey{
		params: params,
		pub:    pub,
		kty:    akpKty,
		alg:    raw.Alg,
		kid:    raw.Kid,
		use:    raw.Use,
	}

	// Derive the private key from the seed member when present.
	if raw.D != "" {
		seed, err := base64.RawURLEncoding.DecodeString(raw.D)
		if err != nil {
			return nil, fmt.Errorf("unable to decode AKP private seed: %w", err)
		}
		priv, err := mldsa.NewPrivateKey(params, seed)
		if err != nil {
			return nil, fmt.Errorf("unable to build ML-DSA private key: %w", err)
		}
		if !priv.PublicKey().Equal(pub) {
			return nil, errors.New("AKP JWK private seed does not match its public key")
		}
		k.priv = priv
	}

	return k, nil
}

// assign copies value into dst when the types are compatible.
func assign(dst, value any) error {
	switch d := dst.(type) {
	case *string:
		s, ok := value.(string)
		if !ok {
			return fmt.Errorf("invalid value type %T for string destination", value)
		}
		*d = s
	case *jwa.KeyType:
		s, ok := value.(jwa.KeyType)
		if !ok {
			return fmt.Errorf("invalid value type %T for jwa.KeyType destination", value)
		}
		*d = s
	case *jwa.KeyAlgorithm:
		s, ok := value.(jwa.KeyAlgorithm)
		if !ok {
			return fmt.Errorf("invalid value type %T for jwa.KeyAlgorithm destination", value)
		}
		*d = s
	case *[]byte:
		s, ok := value.([]byte)
		if !ok {
			return fmt.Errorf("invalid value type %T for []byte destination", value)
		}
		*d = s
	case *any:
		*d = value
		return nil
	default:
		return fmt.Errorf("unsupported destination type %T", dst)
	}
	return nil
}
