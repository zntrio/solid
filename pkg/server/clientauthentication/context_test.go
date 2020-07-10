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

package clientauthentication

import (
	"context"
	"testing"

	corev1 "zntr.io/solid/api/gen/go/oidc/core/v1"

	"github.com/golang/protobuf/ptypes/wrappers"
	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
)

var cmpOpts = []cmp.Option{cmpopts.IgnoreUnexported(wrappers.StringValue{}), cmpopts.IgnoreUnexported(corev1.ClientAuthenticationRequest{}), cmpopts.IgnoreUnexported(corev1.ClientAuthenticationResponse{}), cmpopts.IgnoreUnexported(corev1.Client{}), cmpopts.IgnoreUnexported(corev1.Error{})}

func Test_Context_From(t *testing.T) {
	ctx := context.Background()

	want := &corev1.Client{}
	ctx2 := Inject(ctx, want)
	got, ok := FromContext(ctx2)
	if !ok {
		t.Errorf("client has not the right type")
	}

	if diff := cmp.Diff(got, want, cmpOpts...); diff != "" {
		t.Errorf("clientauthentication.FromContext() res =%s", diff)
	}
}

func Test_contextKey_String(t *testing.T) {
	tests := []struct {
		name string
		c    contextKey
		want string
	}{
		{
			name: "empty",
			want: "zntr.io/solid/pkg/clientauthentication/",
		},
		{
			name: "empty",
			c:    contextKey("auth-client"),
			want: "zntr.io/solid/pkg/clientauthentication/auth-client",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.c.String(); got != tt.want {
				t.Errorf("contextKey.String() = %v, want %v", got, tt.want)
			}
		})
	}
}
