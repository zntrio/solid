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

package sdjwt

import (
	"zntr.io/solid/sdk/token"
)

// IssueOption configures sdjwt Issuer.Issue calls. Options are thin
// wrappers over the sdtoken core options (salt source, decoy counts).
type IssueOption interface {
	apply(*issueConfig)
}

// issueConfig carries the per-Issue configuration resolved from the
// option list; it re-exposes the core sdtoken option values the JWT
// wire format needs.
type issueConfig struct {
	saltFactory func() ([]byte, error)
	decoys      uint
}

type issueOptionFunc func(*issueConfig)

func (f issueOptionFunc) apply(c *issueConfig) { f(c) }

// WithSaltFactory overrides the disclosure salt source (default:
// sdtoken.NewSalt — 128 bits of crypto/rand per disclosure).
func WithSaltFactory(factory func() ([]byte, error)) IssueOption {
	return issueOptionFunc(func(c *issueConfig) {
		c.saltFactory = factory
	})
}

// WithDecoyDigests adds n decoy digests to every _sd array and to every
// array containing "..." redacted elements (RFC 9901 section 5.1).
// RFC 9901 decoys are bare digests with no disclosure object.
func WithDecoyDigests(n uint) IssueOption {
	return issueOptionFunc(func(c *issueConfig) {
		c.decoys = n
	})
}

func newIssueConfig(opts ...IssueOption) *issueConfig {
	c := &issueConfig{}
	for _, opt := range opts {
		if opt != nil {
			opt.apply(c)
		}
	}
	return c
}

// VerifyOption configures sdjwt Verifier construction.
type VerifyOption interface {
	apply(*verifyConfig)
}

// verifyConfig carries the Verifier configuration. Defaults are the
// defensive posture: key binding required, audience and nonce checks
// mandatory, 5-minute KB-JWT freshness window, 60-second leeway.
type verifyConfig struct {
	optionalKeyBinding bool
	audience           string
	nonceValidator     func(string) error
	kbMaxAge           seconds
	leeway             seconds
	expectedTypSuffix  string
	kbKeyProvider      func(processedClaims map[string]any) (token.Verifier, error)
}

type seconds = int64

type verifyOptionFunc func(*verifyConfig)

func (f verifyOptionFunc) apply(c *verifyConfig) { f(c) }

// WithOptionalKeyBinding relaxes the default key-binding-required
// policy (RFC 9901 leaves key binding to verifier policy; the default
// here requires it).
func WithOptionalKeyBinding() VerifyOption {
	return verifyOptionFunc(func(c *verifyConfig) {
		c.optionalKeyBinding = true
	})
}

// WithAudience sets the required KB-JWT audience (mandatory check, not
// an option to disable: RFC 9901 section 7.3 step 5).
func WithAudience(audience string) VerifyOption {
	return verifyOptionFunc(func(c *verifyConfig) {
		c.audience = audience
	})
}

// WithNonceValidator sets the mandatory KB-JWT nonce validator. The
// validator returns a non-nil error to reject a nonce (replay defense).
func WithNonceValidator(validator func(string) error) VerifyOption {
	return verifyOptionFunc(func(c *verifyConfig) {
		c.nonceValidator = validator
	})
}

// WithKeyBindingMaxAge sets the KB-JWT freshness window (default 5
// minutes).
func WithKeyBindingMaxAge(maxAgeSeconds seconds) VerifyOption {
	return verifyOptionFunc(func(c *verifyConfig) {
		c.kbMaxAge = maxAgeSeconds
	})
}

// WithLeeway sets the temporal claim leeway (default 60 seconds).
func WithLeeway(leewaySeconds seconds) VerifyOption {
	return verifyOptionFunc(func(c *verifyConfig) {
		c.leeway = leewaySeconds
	})
}

// WithExpectedTyp overrides the issuer JWT typ expectation (default:
// non-empty typ ending in "+sd-jwt").
func WithExpectedTyp(typ string) VerifyOption {
	return verifyOptionFunc(func(c *verifyConfig) {
		c.expectedTypSuffix = typ
	})
}

// WithKeyBindingKeyProvider overrides the key binding verification key
// source (default: the cnf.jwk member of the processed payload, RFC
// 9901 section 7.3 step 5). When set, the provider resolves the KB-JWT
// verifier from the processed claims — the draft-forten
// sd-jwt-access-token profile uses it to verify the KB-JWT with the
// DPoP proof key instead (its section 5.3: the binding key is the
// DPoP key whose thumbprint equals cnf.jkt). Unset behavior is
// unchanged.
func WithKeyBindingKeyProvider(provider func(processedClaims map[string]any) (token.Verifier, error)) VerifyOption {
	return verifyOptionFunc(func(c *verifyConfig) {
		c.kbKeyProvider = provider
	})
}

func newVerifyConfig(opts ...VerifyOption) *verifyConfig {
	c := &verifyConfig{
		kbMaxAge: 5 * 60,
		leeway:   60,
	}
	for _, opt := range opts {
		if opt != nil {
			opt.apply(c)
		}
	}
	return c
}
