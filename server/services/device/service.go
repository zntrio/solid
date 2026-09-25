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

package device

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	flowv1 "zntr.io/solid/api/oidc/flow/v1"
	sessionv1 "zntr.io/solid/api/oidc/session/v1"
	"zntr.io/solid/oidc"
	"zntr.io/solid/sdk/generator"
	"zntr.io/solid/sdk/rfcerrors"
	sessionstate "zntr.io/solid/sdk/session"
	"zntr.io/solid/sdk/types"
	"zntr.io/solid/server/services"
	"zntr.io/solid/server/storage"
)

type service struct {
	clients            storage.ClientReader
	deviceCodeSessions storage.DeviceCodeSession
	deviceCodes        generator.DeviceCode
	userCodes          generator.DeviceUserCode
	userCodeAttempts   storage.UserCodeAttempts
}

const (
	// deviceSessionTTL bounds device code session lifetime (RFC 10027
	// section 6.1.2: short-lived codes).
	deviceSessionTTL = 120 * time.Second
	// defaultPollInterval is the required polling interval advertised at
	// device authorization time (RFC 8628 section 3.2).
	defaultPollInterval uint64 = 5
	// maxUserCodeAttempts caps wrong-code guesses per subject per window
	// (RFC 8628 section 5.1, RFC 10027 section 6.1.11): <= 5 attempts keeps
	// a 34.6-bit user code at ~2^-32 guess probability per window.
	maxUserCodeAttempts = 5
	// userCodeAttemptWindow is the failure-counting window.
	userCodeAttemptWindow = 5 * time.Minute
)

// New build and returns an authorization service implementation.
func New(clients storage.ClientReader, deviceCodeSessions storage.DeviceCodeSession, deviceCodes generator.DeviceCode, userCodes generator.DeviceUserCode, userCodeAttempts storage.UserCodeAttempts) services.Device {
	return &service{
		clients:            clients,
		deviceCodeSessions: deviceCodeSessions,
		deviceCodes:        deviceCodes,
		userCodes:          userCodes,
		userCodeAttempts:   userCodeAttempts,
	}
}

var timeFunc = time.Now

// -----------------------------------------------------------------------------

func (s *service) Authorize(ctx context.Context, req *flowv1.DeviceAuthorizationRequest) (*flowv1.DeviceAuthorizationResponse, error) {
	res := &flowv1.DeviceAuthorizationResponse{}

	// Check req nullity
	if req == nil {
		res.Error = rfcerrors.InvalidRequest().Build()
		return res, fmt.Errorf("unable to process nil request")
	}

	// Check issuer
	if req.Issuer == "" {
		res.Error = rfcerrors.InvalidRequest().Build()
		return res, fmt.Errorf("unable to process empty issuer")
	}

	// Check client_id
	if req.ClientId == "" {
		res.Error = rfcerrors.InvalidRequest().Build()
		return res, fmt.Errorf("client_id must not be empty")
	}

	// Check client existence
	client, err := s.clients.Get(ctx, req.ClientId)
	if err != nil {
		res.Error = rfcerrors.InvalidRequest().Build()
		return res, fmt.Errorf("unable to retrieve client details: %w", err)
	}
	if client == nil {
		res.Error = rfcerrors.InvalidClient().Build()
		return res, fmt.Errorf("unable to process with nil client")
	}

	// Validate client capabilities
	if !types.StringArray(client.GrantTypes).Contains(oidc.GrantTypeDeviceCode) {
		res.Error = rfcerrors.UnsupportedGrantType().Build()
		return res, fmt.Errorf("client doesn't support '%s' as grant type", oidc.GrantTypeDeviceCode)
	}

	// Generate device code
	deviceCode, err := s.deviceCodes.Generate(ctx, req.Issuer)
	if err != nil {
		res.Error = rfcerrors.ServerError().Build()
		return res, fmt.Errorf("unable to generate device code: %w", err)
	}

	// Generate device code
	userCode, err := s.userCodes.Generate(ctx, req.Issuer)
	if err != nil {
		res.Error = rfcerrors.ServerError().Build()
		return res, fmt.Errorf("unable to generate user code: %w", err)
	}

	// Prepare session. The in-memory registration TTL is 120 seconds; the
	// absolute expiry is stamped so that the token grant can distinguish an
	// expired session from a pending one (RFC 8628 section 3.5).
	session := &sessionv1.DeviceCodeSession{
		Issuer:     req.Issuer,
		Client:     client,
		Request:    req,
		Scope:      req.Scope,
		Audience:   req.Audience,
		DeviceCode: deviceCode,
		Status:     sessionv1.DeviceCodeStatus_DEVICE_CODE_STATUS_AUTHORIZATION_PENDING,
		ExpiresAt:  uint64(time.Now().Add(deviceSessionTTL).Unix()),
		// Advertised polling interval (RFC 8628 section 3.2); the token
		// grant enforces it with slow_down (RFC 8628 section 3.5).
		PollInterval: defaultPollInterval,
		// RFC 9396 section 3: authorization details requested with the
		// device authorization request are stored on the session and shown
		// at consent time.
		AuthorizationDetails: req.AuthorizationDetails,
	}

	// RFC 10027 section 6.1.9: the cross-device channel is unauthenticated
	// and has no consent gate, so the device grant never grants offline
	// access — strip it from the session scope before storing.
	if req.Scope != nil {
		scopes := types.StringArray(strings.Fields(*req.Scope))
		scopes.Remove(oidc.ScopeOfflineAccess)
		filtered := strings.Join(scopes, " ")
		session.Scope = &filtered
	}

	// Store device code request
	expiresIn, err := s.deviceCodeSessions.Register(ctx, req.Issuer, userCode, session)
	if err != nil {
		res.Error = rfcerrors.ServerError().Build()
		return res, fmt.Errorf("unable to create device request: %w", err)
	}
	_ = expiresIn

	// Assign device code
	res.DeviceCode = deviceCode
	// Assign user code
	res.UserCode = userCode
	// Set expiration
	res.ExpiresIn = expiresIn
	// Polling interval
	res.Interval = defaultPollInterval
	// Assign issuer
	res.Issuer = req.Issuer

	// No error
	return res, nil
}

func (s *service) Validate(ctx context.Context, req *flowv1.DeviceCodeValidationRequest) (*flowv1.DeviceCodeValidationResponse, error) {
	res := &flowv1.DeviceCodeValidationResponse{}

	// Check req nullity
	if req == nil {
		res.Error = rfcerrors.InvalidRequest().Build()
		return res, fmt.Errorf("unable to process nil request")
	}

	// Check issuer
	if req.Issuer == "" {
		res.Error = rfcerrors.InvalidRequest().Build()
		return res, fmt.Errorf("unable to process empty issuer")
	}

	// Check user code
	if req.UserCode == "" {
		res.Error = rfcerrors.InvalidRequest().Build()
		return res, fmt.Errorf("unable to process blank user_code")
	}

	// Check subject
	if req.Subject == "" {
		res.Error = rfcerrors.InvalidRequest().Build()
		return res, fmt.Errorf("unable to process blank subject")
	}

	// RFC 8628 section 5.1 / RFC 10027 section 6.1.11: throttle
	// user-code brute-forcing per (issuer, subject); a global cap would
	// DoS legitimate users, per-subject is the standard trade-off.
	attemptsKey := req.Issuer + "\x00" + req.Subject
	if s.userCodeAttempts.Failures(ctx, attemptsKey) >= maxUserCodeAttempts {
		res.Error = rfcerrors.AccessDenied().Build()
		return res, fmt.Errorf("too many failed attempts for subject '%s'", req.Subject)
	}

	// Resolve device code
	session, err := s.deviceCodeSessions.GetByUserCode(ctx, req.Issuer, req.UserCode)
	if err != nil {
		if !errors.Is(err, storage.ErrNotFound) {
			res.Error = rfcerrors.ServerError().Build()
		} else {
			// Unknown user code: record the failure for throttling
			// (RFC 8628 section 5.1). Expiry (expired_token) does not
			// count as a failure.
			_ = s.userCodeAttempts.Fail(ctx, attemptsKey, userCodeAttemptWindow)
			res.Error = rfcerrors.InvalidRequest().Build()
		}
		return res, fmt.Errorf("session is invalid")
	}
	if session == nil {
		res.Error = rfcerrors.InvalidRequest().Build()
		return res, fmt.Errorf("retrieved nil session for '%s'", req.UserCode)
	}
	if session.Request == nil {
		res.Error = rfcerrors.InvalidRequest().Build()
		return res, fmt.Errorf("session has nil request for '%s'", req.UserCode)
	}
	if session.Client == nil {
		res.Error = rfcerrors.InvalidRequest().Build()
		return res, fmt.Errorf("session has nil client for '%s'", req.UserCode)
	}

	// Check expiration
	if session.ExpiresAt < uint64(timeFunc().Unix()) {
		res.Error = rfcerrors.TokenExpired().Build()
		return res, fmt.Errorf("user_code '%s' is expired", req.UserCode)
	}

	// Apply the session state machine: AUTHORIZATION_PENDING -> VALIDATED is
	// the only legal transition; anything else (double authorization, replay)
	// is rejected by construction.
	if err := sessionstate.DeviceCodeTransition(session.Status, sessionv1.DeviceCodeStatus_DEVICE_CODE_STATUS_VALIDATED); err != nil {
		res.Error = rfcerrors.InvalidRequest().Build()
		return res, fmt.Errorf("user_code '%s' cannot be authorized: %w", req.UserCode, err)
	}

	// Update session
	session.Subject = new(req.Subject)
	session.Status = sessionv1.DeviceCodeStatus_DEVICE_CODE_STATUS_VALIDATED

	// Update ephemeral storage
	if err := s.deviceCodeSessions.Validate(ctx, req.Issuer, req.UserCode, session); err != nil {
		res.Error = rfcerrors.ServerError().Build()
		return res, fmt.Errorf("user_code '%s' could not be authorized: %w", req.UserCode, err)
	}

	// Delete request
	if err := s.deviceCodeSessions.Delete(ctx, req.Issuer, req.UserCode); err != nil {
		res.Error = rfcerrors.ServerError().Build()
		return res, fmt.Errorf("user authorization '%s' could not be deleted: %w", req.UserCode, err)
	}

	// Successful validation resets the per-subject failure counter, so
	// legitimate users are never locked out by an attacker's failures.
	s.userCodeAttempts.Reset(ctx, attemptsKey)

	// No error
	return res, nil
}

// Deny refuses a device authorization request: the session moves to the
// terminal DENIED state and the token grant reports access_denied on the
// next poll (RFC 8628 section 3.5).
func (s *service) Deny(ctx context.Context, req *flowv1.DeviceCodeValidationRequest) (*flowv1.DeviceCodeValidationResponse, error) {
	res := &flowv1.DeviceCodeValidationResponse{}

	// Check req nullity
	if req == nil {
		res.Error = rfcerrors.InvalidRequest().Build()
		return res, fmt.Errorf("unable to process nil request")
	}

	// Check issuer
	if req.Issuer == "" {
		res.Error = rfcerrors.InvalidRequest().Build()
		return res, fmt.Errorf("unable to process empty issuer")
	}

	// Check user code
	if req.UserCode == "" {
		res.Error = rfcerrors.InvalidRequest().Build()
		return res, fmt.Errorf("unable to process blank user_code")
	}

	// Deliberately not throttled: brute-forcing the deny path only griefs
	// the attacker's own code discovery (RFC 8628 section 5.1).

	// Resolve device code
	session, err := s.deviceCodeSessions.GetByUserCode(ctx, req.Issuer, req.UserCode)
	if err != nil {
		if !errors.Is(err, storage.ErrNotFound) {
			res.Error = rfcerrors.ServerError().Build()
		} else {
			res.Error = rfcerrors.InvalidRequest().Build()
		}
		return res, fmt.Errorf("session is invalid")
	}

	// Check session
	if session == nil {
		res.Error = rfcerrors.InvalidRequest().Build()
		return res, fmt.Errorf("retrieved nil session for '%s'", req.UserCode)
	}

	// Apply the session state machine: AUTHORIZATION_PENDING -> DENIED is
	// the only legal transition; anything else (double handling, replay)
	// is rejected by construction.
	if err := sessionstate.DeviceCodeTransition(session.Status, sessionv1.DeviceCodeStatus_DEVICE_CODE_STATUS_DENIED); err != nil {
		res.Error = rfcerrors.InvalidRequest().Build()
		return res, fmt.Errorf("user_code '%s' cannot be denied: %w", req.UserCode, err)
	}

	// Update session
	session.Status = sessionv1.DeviceCodeStatus_DEVICE_CODE_STATUS_DENIED

	// Update ephemeral storage
	if err := s.deviceCodeSessions.Validate(ctx, req.Issuer, req.UserCode, session); err != nil {
		res.Error = rfcerrors.ServerError().Build()
		return res, fmt.Errorf("user_code '%s' could not be denied: %w", req.UserCode, err)
	}

	// No error
	return res, nil
}
