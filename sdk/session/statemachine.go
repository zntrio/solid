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

// Package session centralizes the lifecycle state machines of authorization
// server sessions. Transitions are explicit and terminal: every session
// status change must go through this package so that illegal transitions
// (replay, rollback) are rejected by construction rather than by scattered
// ad-hoc comparisons in services.
package session

import (
	"fmt"

	sessionv1 "zntr.io/solid/api/oidc/session/v1"
)

// deviceCodeTransitions is the exhaustive transition table for device code
// sessions (RFC 8628): a session is created AUTHORIZATION_PENDING and may
// only move to VALIDATED once, when the end user completes authorization, or
// to DENIED when the end user refuses it. Both states are terminal; the
// token grant consumes VALIDATED sessions and rejects DENIED ones.
var deviceCodeTransitions = map[sessionv1.DeviceCodeStatus]map[sessionv1.DeviceCodeStatus]struct{}{
	sessionv1.DeviceCodeStatus_DEVICE_CODE_STATUS_AUTHORIZATION_PENDING: {
		sessionv1.DeviceCodeStatus_DEVICE_CODE_STATUS_VALIDATED: {},
		sessionv1.DeviceCodeStatus_DEVICE_CODE_STATUS_DENIED:    {},
	},
}

// DeviceCodeTransition validates a device code session status change.
// It returns an error when the transition is not permitted by the state
// machine; the caller MUST abort the operation in that case.
func DeviceCodeTransition(from, to sessionv1.DeviceCodeStatus) error {
	if from == to {
		return fmt.Errorf("invalid device code session transition: %s is terminal", from)
	}
	allowed, ok := deviceCodeTransitions[from]
	if !ok {
		return fmt.Errorf("invalid device code session transition: no transition from %s", from)
	}
	if _, ok := allowed[to]; !ok {
		return fmt.Errorf("invalid device code session transition: %s -> %s is not allowed", from, to)
	}
	return nil
}

// authorizationCodeTransitions is the exhaustive transition table for
// authorization code sessions (RFC 6749 section 4.1.2): a code is created
// ACTIVE and may be consumed exactly once. CONSUMED is terminal; a second
// redemption attempt is a replay and MUST be rejected.
var authorizationCodeTransitions = map[sessionv1.AuthorizationCodeStatus]map[sessionv1.AuthorizationCodeStatus]struct{}{
	sessionv1.AuthorizationCodeStatus_AUTHORIZATION_CODE_STATUS_ACTIVE: {
		sessionv1.AuthorizationCodeStatus_AUTHORIZATION_CODE_STATUS_CONSUMED: {},
	},
}

// AuthorizationCodeTransition validates an authorization code session status
// change. It returns an error when the transition is not permitted by the
// state machine; the caller MUST abort the operation in that case.
func AuthorizationCodeTransition(from, to sessionv1.AuthorizationCodeStatus) error {
	if from == to {
		return fmt.Errorf("invalid authorization code session transition: %s is terminal", from)
	}
	allowed, ok := authorizationCodeTransitions[from]
	if !ok {
		return fmt.Errorf("invalid authorization code session transition: no transition from %s", from)
	}
	if _, ok := allowed[to]; !ok {
		return fmt.Errorf("invalid authorization code session transition: %s -> %s is not allowed", from, to)
	}
	return nil
}
