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

package session

import (
	"testing"

	sessionv1 "zntr.io/solid/api/oidc/session/v1"
)

func TestDeviceCodeTransition(t *testing.T) {
	tests := []struct {
		name    string
		from    sessionv1.DeviceCodeStatus
		to      sessionv1.DeviceCodeStatus
		wantErr bool
	}{
		{
			name: "pending to validated",
			from: sessionv1.DeviceCodeStatus_DEVICE_CODE_STATUS_AUTHORIZATION_PENDING,
			to:   sessionv1.DeviceCodeStatus_DEVICE_CODE_STATUS_VALIDATED,
		},
		{
			name:    "validated to pending is forbidden",
			from:    sessionv1.DeviceCodeStatus_DEVICE_CODE_STATUS_VALIDATED,
			to:      sessionv1.DeviceCodeStatus_DEVICE_CODE_STATUS_AUTHORIZATION_PENDING,
			wantErr: true,
		},
		{
			name:    "validated to validated is forbidden (no replay)",
			from:    sessionv1.DeviceCodeStatus_DEVICE_CODE_STATUS_VALIDATED,
			to:      sessionv1.DeviceCodeStatus_DEVICE_CODE_STATUS_VALIDATED,
			wantErr: true,
		},
		{
			name:    "unspecified to validated is forbidden",
			from:    sessionv1.DeviceCodeStatus_DEVICE_CODE_STATUS_UNSPECIFIED,
			to:      sessionv1.DeviceCodeStatus_DEVICE_CODE_STATUS_VALIDATED,
			wantErr: true,
		},
		{
			name:    "unknown to anything is forbidden",
			from:    sessionv1.DeviceCodeStatus_DEVICE_CODE_STATUS_UNKNOWN,
			to:      sessionv1.DeviceCodeStatus_DEVICE_CODE_STATUS_VALIDATED,
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := DeviceCodeTransition(tt.from, tt.to)
			if (err != nil) != tt.wantErr {
				t.Errorf("DeviceCodeTransition(%v, %v) error = %v, wantErr %v", tt.from, tt.to, err, tt.wantErr)
			}
		})
	}
}

func TestAuthorizationCodeTransition(t *testing.T) {
	tests := []struct {
		name    string
		from    sessionv1.AuthorizationCodeStatus
		to      sessionv1.AuthorizationCodeStatus
		wantErr bool
	}{
		{
			name: "active to consumed",
			from: sessionv1.AuthorizationCodeStatus_AUTHORIZATION_CODE_STATUS_ACTIVE,
			to:   sessionv1.AuthorizationCodeStatus_AUTHORIZATION_CODE_STATUS_CONSUMED,
		},
		{
			name:    "consumed to active is forbidden (no replay)",
			from:    sessionv1.AuthorizationCodeStatus_AUTHORIZATION_CODE_STATUS_CONSUMED,
			to:      sessionv1.AuthorizationCodeStatus_AUTHORIZATION_CODE_STATUS_ACTIVE,
			wantErr: true,
		},
		{
			name:    "consumed to consumed is forbidden (no replay)",
			from:    sessionv1.AuthorizationCodeStatus_AUTHORIZATION_CODE_STATUS_CONSUMED,
			to:      sessionv1.AuthorizationCodeStatus_AUTHORIZATION_CODE_STATUS_CONSUMED,
			wantErr: true,
		},
		{
			name:    "unspecified to consumed is forbidden",
			from:    sessionv1.AuthorizationCodeStatus_AUTHORIZATION_CODE_STATUS_UNSPECIFIED,
			to:      sessionv1.AuthorizationCodeStatus_AUTHORIZATION_CODE_STATUS_CONSUMED,
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := AuthorizationCodeTransition(tt.from, tt.to)
			if (err != nil) != tt.wantErr {
				t.Errorf("AuthorizationCodeTransition(%v, %v) error = %v, wantErr %v", tt.from, tt.to, err, tt.wantErr)
			}
		})
	}
}
