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
	"fmt"
	"time"

	corev1 "zntr.io/solid/api/oidc/core/v1"
	"zntr.io/solid/oidc"
	"zntr.io/solid/sdk/rfcerrors"
	"zntr.io/solid/sdk/types"
	"zntr.io/solid/server/services"
	"zntr.io/solid/server/storage"
)

type service struct {
	clients            storage.ClientReader
	deviceCodeSessions storage.DeviceCodeSession
}

// New build and returns an authorization service implementation.
func New(clients storage.ClientReader, deviceCodeSessions storage.DeviceCodeSession) services.Device {
	return &service{
		clients:            clients,
		deviceCodeSessions: deviceCodeSessions,
	}
}

var timeFunc = time.Now

// -----------------------------------------------------------------------------

func (s *service) Authorize(ctx context.Context, req *corev1.DeviceAuthorizationRequest) (*corev1.DeviceAuthorizationResponse, error) {
	res := &corev1.DeviceAuthorizationResponse{}

	// Check req nullity
	if req == nil {
		res.Error = rfcerrors.InvalidRequest().Build()
		return res, fmt.Errorf("unable to process nil request")
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

	// Prepare session
	session := &corev1.DeviceCodeSession{
		Client:  client,
		Request: req,
	}
	if req.Scope != nil {
		session.Scope = *req.Scope
	}
	if req.Audience != nil {
		session.Audience = *req.Audience
	}

	// Store device code request
	deviceCode, userCode, expiresIn, err := s.deviceCodeSessions.Register(ctx, session)
	if err != nil {
		res.Error = rfcerrors.ServerError().Build()
		return res, fmt.Errorf("unable to create device request: %w", err)
	}

	// Assign device code
	res.DeviceCode = deviceCode
	// Assign user code
	res.UserCode = userCode
	// Set expiration
	res.ExpiresIn = expiresIn
	// Polling interval
	res.Interval = 5

	// No error
	return res, nil
}

func (s *service) Validate(ctx context.Context, req *corev1.DeviceCodeValidationRequest) (*corev1.DeviceCodeValidationResponse, error) {
	res := &corev1.DeviceCodeValidationResponse{}

	// Check req nullity
	if req == nil {
		res.Error = rfcerrors.InvalidRequest().Build()
		return res, fmt.Errorf("unable to process nil request")
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

	// Resolve device code
	session, err := s.deviceCodeSessions.GetByUserCode(ctx, req.UserCode)
	if err != nil {
		if err != storage.ErrNotFound {
			res.Error = rfcerrors.ServerError().Build()
		} else {
			res.Error = rfcerrors.InvalidRequest().Build()
		}
		return res, fmt.Errorf("session is invalid")
	}

	// Check session
	if session == nil {
		res.Error = rfcerrors.ServerError().Build()
		return res, fmt.Errorf("retrieved nil session for '%s'", req.UserCode)
	}
	if session.Request == nil {
		res.Error = rfcerrors.ServerError().Build()
		return res, fmt.Errorf("session has nil request for '%s'", req.UserCode)
	}
	if session.Client == nil {
		res.Error = rfcerrors.ServerError().Build()
		return res, fmt.Errorf("session has nil client for '%s'", req.UserCode)
	}

	// Check expiration
	if session.ExpiresAt < uint64(timeFunc().Unix()) {
		res.Error = rfcerrors.TokenExpired().Build()
		return res, fmt.Errorf("user_code '%s' is expired", req.UserCode)
	}

	// Check if it validated
	if session.Status != corev1.DeviceCodeStatus_DEVICE_CODE_STATUS_AUTHORIZATION_PENDING {
		res.Error = rfcerrors.InvalidRequest().Build()
		return res, fmt.Errorf("user_code '%s' is already authorized", req.UserCode)
	}

	// Update ephemeral storage
	if err := s.deviceCodeSessions.Authorize(ctx, session.UserCode, req.Subject); err != nil {
		res.Error = rfcerrors.ServerError().Build()
		return res, fmt.Errorf("user_code '%s' could not be authorized: %v", req.UserCode, err)
	}

	// No error
	return res, nil
}
