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

	corev1 "go.zenithar.org/solid/api/gen/go/oidc/core/v1"
	"go.zenithar.org/solid/api/oidc"
	"go.zenithar.org/solid/internal/services"
	"go.zenithar.org/solid/pkg/generator"
	"go.zenithar.org/solid/pkg/rfcerrors"
	"go.zenithar.org/solid/pkg/storage"
	"go.zenithar.org/solid/pkg/types"
)

type service struct {
	clients            storage.ClientReader
	deviceCodeSessions storage.DeviceCodeSessionWriter
	userCodeGen        generator.DeviceUserCode
}

// New build and returns an authorization service implementation.
func New(clients storage.ClientReader, deviceCodeSessions storage.DeviceCodeSessionWriter) services.Device {
	return &service{
		clients:            clients,
		deviceCodeSessions: deviceCodeSessions,
	}
}

// -----------------------------------------------------------------------------

func (s *service) Authorize(ctx context.Context, req *corev1.DeviceAuthorizationRequest) (*corev1.DeviceAuthorizationResponse, error) {
	res := &corev1.DeviceAuthorizationResponse{}

	// Check req nullity
	if req == nil {
		res.Error = rfcerrors.InvalidRequest("")
		return res, fmt.Errorf("unable to process nil request")
	}

	// Check client_id
	if req.ClientId == "" {
		res.Error = rfcerrors.InvalidRequest("")
		return res, fmt.Errorf("client_id must not be empty")
	}

	// Check client existence
	client, err := s.clients.Get(ctx, req.ClientId)
	if err != nil {
		res.Error = rfcerrors.InvalidRequest("")
		return res, fmt.Errorf("unable to retrieve client details: %w", err)
	}

	// Validate client capabilities
	if !types.StringArray(client.GrantTypes).Contains(oidc.GrantTypeDeviceCode) {
		res.Error = rfcerrors.UnsupportedGrantType("")
		return res, fmt.Errorf("client doesn't support '%s' as grant type", oidc.GrantTypeDeviceCode)
	}

	// Store device code request
	deviceCode, userCode, err := s.deviceCodeSessions.Register(ctx, &corev1.DeviceCodeSession{
		Client:  client,
		Request: req,
	})
	if err != nil {
		res.Error = rfcerrors.ServerError("")
		return res, fmt.Errorf("unable to create device request: %w", err)
	}

	// Assign device code
	res.DeviceCode = deviceCode
	// Assign user code
	res.UserCode = userCode
	// Set expiration
	res.ExpiresIn = 120 // 2 minutes
	// Polling interval
	res.Interval = 5

	// No error
	return res, nil
}
