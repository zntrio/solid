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

package sdcwt

import "time"

// IssueOption configures sdcwt Issuer.Issue calls.
type IssueOption interface {
	apply(*issueConfig)
}

// issueConfig carries the per-Issue configuration.
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

// WithDecoyDigests adds n decoy digests per redacted_claim_keys array
// and per array containing tag-60 elements (draft section 10). Each
// decoy also produces a 1-element decoy disclosure the Holder must
// hold.
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

// KeyBindOption configures Holder.KeyBind.
type KeyBindOption interface {
	apply(*keyBindConfig)
}

// keyBindConfig carries the KeyBind configuration: iat or cti (one
// REQUIRED, draft section 8.1).
type keyBindConfig struct {
	issuedAt int64
	cti      []byte
}

type keyBindOptionFunc func(*keyBindConfig)

func (f keyBindOptionFunc) apply(c *keyBindConfig) { f(c) }

// WithIssuedAt sets the KBT iat claim (default: now).
func WithIssuedAt(issuedAt int64) KeyBindOption {
	return keyBindOptionFunc(func(c *keyBindConfig) {
		c.issuedAt = issuedAt
	})
}

// WithCti sets the KBT cti claim (token id). When set, cti is used
// instead of iat.
func WithCti(cti []byte) KeyBindOption {
	return keyBindOptionFunc(func(c *keyBindConfig) {
		c.cti = cti
	})
}

func newKeyBindConfig(opts ...KeyBindOption) *keyBindConfig {
	c := &keyBindConfig{
		issuedAt: time.Now().Unix(),
	}
	for _, opt := range opts {
		if opt != nil {
			opt.apply(c)
		}
	}
	return c
}

// VerifyOption configures sdcwt Verifier construction.
type VerifyOption interface {
	apply(*verifyConfig)
}

// verifyConfig carries the Verifier configuration. Audience and cnonce
// validation are mandatory (draft section 9: SHOULD promoted to MUST).
type verifyConfig struct {
	audience        string
	cnonceValidator func([]byte) error
	leeway          time.Duration
}

type verifyOptionFunc func(*verifyConfig)

func (f verifyOptionFunc) apply(c *verifyConfig) { f(c) }

// WithAudience sets the required audience (mandatory option).
func WithAudience(audience string) VerifyOption {
	return verifyOptionFunc(func(c *verifyConfig) {
		c.audience = audience
	})
}

// WithCnonceValidator sets the mandatory cnonce validator. The
// validator returns a non-nil error to reject a cnonce (replay
// defense).
func WithCnonceValidator(validator func([]byte) error) VerifyOption {
	return verifyOptionFunc(func(c *verifyConfig) {
		c.cnonceValidator = validator
	})
}

// WithLeeway sets the temporal claim leeway (default 60 seconds).
func WithLeeway(leeway time.Duration) VerifyOption {
	return verifyOptionFunc(func(c *verifyConfig) {
		c.leeway = leeway
	})
}

func newVerifyConfig(opts ...VerifyOption) *verifyConfig {
	c := &verifyConfig{
		leeway: 60 * time.Second,
	}
	for _, opt := range opts {
		if opt != nil {
			opt.apply(c)
		}
	}
	return c
}
