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

package authorization

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	flowv1 "zntr.io/solid/api/oidc/flow/v1"
	tokenv1 "zntr.io/solid/api/oidc/token/v1"
	"zntr.io/solid/oidc"
)

// Test_validateStepUpRequirements covers the RFC 9470 section 4/5 matrix:
// acr_values membership (single and multi-valued), max_age freshness, the
// fail-closed posture without an event, the adversarial degenerate events,
// and the boundary case now == auth_time+max_age (passes).
func Test_validateStepUpRequirements(t *testing.T) {
	acr := func(v string) *string { return &v }
	age := func(v uint64) *uint64 { return &v }

	// Freeze the clock.
	frozen := time.Unix(1_000_000, 0)
	original := timeFunc
	timeFunc = func() time.Time { return frozen }
	t.Cleanup(func() { timeFunc = original })

	tests := []struct {
		name      string
		req       *flowv1.AuthorizationRequest
		ev        *tokenv1.AuthEvent
		wantErr   string // empty means success
		wantState string
	}{
		{
			name: "no step-up parameters, no event",
			req:  &flowv1.AuthorizationRequest{},
			ev:   nil,
		},
		{
			name: "acr hit",
			req: &flowv1.AuthorizationRequest{
				State:     "s1",
				AcrValues: acr("urn:solid:loa:1fa:any"),
			},
			ev: &tokenv1.AuthEvent{Acr: acr("urn:solid:loa:1fa:any"), AuthTime: age(999_999)},
		},
		{
			name: "acr hit among multiple requested values",
			req: &flowv1.AuthorizationRequest{
				State:     "s2",
				AcrValues: acr("urn:solid:loa:2fa:hard urn:solid:loa:1fa:any"),
			},
			ev: &tokenv1.AuthEvent{Acr: acr("urn:solid:loa:1fa:any"), AuthTime: age(999_999)},
		},
		{
			name: "acr miss",
			req: &flowv1.AuthorizationRequest{
				State:     "s3",
				AcrValues: acr("urn:solid:loa:2fa:hard"),
			},
			ev:        &tokenv1.AuthEvent{Acr: acr("urn:solid:loa:1fa:any"), AuthTime: age(999_999)},
			wantErr:   oidc.ErrorUnmetAuthenticationRequirements,
			wantState: "s3",
		},
		{
			name: "acr_values without event",
			req: &flowv1.AuthorizationRequest{
				State:     "s4",
				AcrValues: acr("urn:solid:loa:1fa:any"),
			},
			ev:        nil,
			wantErr:   oidc.ErrorUnmetAuthenticationRequirements,
			wantState: "s4",
		},
		{
			name: "empty achieved acr is a member of no requested values",
			req: &flowv1.AuthorizationRequest{
				State:     "s5",
				AcrValues: acr("urn:solid:loa:1fa:any"),
			},
			ev:        &tokenv1.AuthEvent{Acr: acr(""), AuthTime: age(999_999)},
			wantErr:   oidc.ErrorUnmetAuthenticationRequirements,
			wantState: "s5",
		},
		{
			name: "max_age fresh login passes",
			req: &flowv1.AuthorizationRequest{
				State:  "s6",
				MaxAge: age(60),
			},
			ev: &tokenv1.AuthEvent{Acr: acr("urn:solid:loa:1fa:any"), AuthTime: age(999_960)},
		},
		{
			name: "max_age boundary now == auth_time+max_age passes",
			req: &flowv1.AuthorizationRequest{
				State:  "s7",
				MaxAge: age(40),
			},
			ev: &tokenv1.AuthEvent{Acr: acr("urn:solid:loa:1fa:any"), AuthTime: age(999_960)},
		},
		{
			name: "max_age stale login fails",
			req: &flowv1.AuthorizationRequest{
				State:  "s8",
				MaxAge: age(5),
			},
			ev:        &tokenv1.AuthEvent{Acr: acr("urn:solid:loa:1fa:any"), AuthTime: age(999_360)},
			wantErr:   oidc.ErrorUnmetAuthenticationRequirements,
			wantState: "s8",
		},
		{
			name: "max_age without event",
			req: &flowv1.AuthorizationRequest{
				State:  "s9",
				MaxAge: age(60),
			},
			ev:        nil,
			wantErr:   oidc.ErrorUnmetAuthenticationRequirements,
			wantState: "s9",
		},
		{
			name: "max_age with zero auth_time fails",
			req: &flowv1.AuthorizationRequest{
				State:  "s10",
				MaxAge: age(60),
			},
			ev:        &tokenv1.AuthEvent{Acr: acr("urn:solid:loa:1fa:any"), AuthTime: age(0)},
			wantErr:   oidc.ErrorUnmetAuthenticationRequirements,
			wantState: "s10",
		},
		{
			name: "max_age with missing auth_time fails",
			req: &flowv1.AuthorizationRequest{
				State:  "s11",
				MaxAge: age(60),
			},
			ev:        &tokenv1.AuthEvent{Acr: acr("urn:solid:loa:1fa:any")},
			wantErr:   oidc.ErrorUnmetAuthenticationRequirements,
			wantState: "s11",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			publicErr, err := validateStepUpRequirements(tt.req, tt.ev)
			if tt.wantErr == "" {
				require.NoError(t, err)
				require.Nil(t, publicErr)
				return
			}
			require.Error(t, err)
			require.NotNil(t, publicErr)
			require.Equal(t, tt.wantErr, publicErr.Error)
			require.Equal(t, tt.wantState, *publicErr.State)
		})
	}
}
