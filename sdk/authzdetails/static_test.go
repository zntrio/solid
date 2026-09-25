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

package authzdetails

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	tokenv1 "zntr.io/solid/api/oidc/token/v1"
)

func TestStaticValidator_Validate(t *testing.T) {
	v := NewStaticValidator(map[string]struct{}{
		"payment_initiation": {},
	})

	t.Run("empty", func(t *testing.T) {
		assert.NoError(t, v.Validate(context.Background(), nil))
	})

	t.Run("supported type", func(t *testing.T) {
		err := v.Validate(context.Background(), []*tokenv1.AuthorizationDetail{
			{Type: "payment_initiation", Actions: []string{"initiate"}},
		})
		require.NoError(t, err)
	})

	t.Run("unsupported type", func(t *testing.T) {
		err := v.Validate(context.Background(), []*tokenv1.AuthorizationDetail{
			{Type: "account_information"},
		})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "unsupported type")
	})

	t.Run("mixed entries", func(t *testing.T) {
		err := v.Validate(context.Background(), []*tokenv1.AuthorizationDetail{
			{Type: "payment_initiation"},
			{Type: "unknown_type"},
		})
		require.Error(t, err)
	})

	t.Run("nil entry", func(t *testing.T) {
		err := v.Validate(context.Background(), []*tokenv1.AuthorizationDetail{nil})
		require.Error(t, err)
	})

	t.Run("nil validator fails closed", func(t *testing.T) {
		var nilValidator *StaticValidator
		err := nilValidator.Validate(context.Background(), []*tokenv1.AuthorizationDetail{
			{Type: "payment_initiation"},
		})
		require.Error(t, err)
	})
}
