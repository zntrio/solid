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

package token

import (
	"testing"

	"github.com/stretchr/testify/require"

	tokenv1 "zntr.io/solid/api/oidc/token/v1"
)

func Test_validateAuthorizationDetailsSubset(t *testing.T) {
	payment := &tokenv1.AuthorizationDetail{Type: "payment"}
	account := &tokenv1.AuthorizationDetail{Type: "account"}
	transaction := &tokenv1.AuthorizationDetail{Type: "transaction"}

	tests := []struct {
		name      string
		requested []*tokenv1.AuthorizationDetail
		granted   []*tokenv1.AuthorizationDetail
		wantErr   string
	}{
		{
			name:      "nil requested is a no-op",
			requested: nil,
			granted:   nil,
		},
		{
			name:      "empty requested is a no-op",
			requested: []*tokenv1.AuthorizationDetail{},
			granted:   []*tokenv1.AuthorizationDetail{payment},
		},
		{
			name:      "null requested entry is rejected",
			requested: []*tokenv1.AuthorizationDetail{nil},
			granted:   []*tokenv1.AuthorizationDetail{payment},
			wantErr:   "authorization_details[0]: entry must not be null",
		},
		{
			name:      "exact match",
			requested: []*tokenv1.AuthorizationDetail{payment},
			granted:   []*tokenv1.AuthorizationDetail{payment},
		},
		{
			name:      "match among multiple granted entries",
			requested: []*tokenv1.AuthorizationDetail{account},
			granted:   []*tokenv1.AuthorizationDetail{payment, account, transaction},
		},
		{
			name:      "null granted entries are skipped",
			requested: []*tokenv1.AuthorizationDetail{payment},
			granted:   []*tokenv1.AuthorizationDetail{nil, payment},
		},
		{
			name:      "no match",
			requested: []*tokenv1.AuthorizationDetail{payment},
			granted:   []*tokenv1.AuthorizationDetail{account},
			wantErr:   `authorization_details[0] of type "payment" was not consented in the authorization grant`,
		},
		{
			name:      "empty granted set never matches",
			requested: []*tokenv1.AuthorizationDetail{payment},
			granted:   []*tokenv1.AuthorizationDetail{},
			wantErr:   `authorization_details[0] of type "payment" was not consented in the authorization grant`,
		},
		{
			name:      "all requested entries must match",
			requested: []*tokenv1.AuthorizationDetail{payment, transaction},
			granted:   []*tokenv1.AuthorizationDetail{payment},
			wantErr:   `authorization_details[1] of type "transaction" was not consented in the authorization grant`,
		},
		{
			name:      "distinct entries of the same type are not interchangeable",
			requested: []*tokenv1.AuthorizationDetail{{Type: "payment", Actions: []string{"withdrawal"}}},
			granted:   []*tokenv1.AuthorizationDetail{{Type: "payment", Actions: []string{"transfer"}}},
			wantErr:   `authorization_details[0] of type "payment" was not consented in the authorization grant`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateAuthorizationDetailsSubset(tt.requested, tt.granted)
			if tt.wantErr == "" {
				require.NoError(t, err)
				return
			}
			require.EqualError(t, err, tt.wantErr)
		})
	}
}
