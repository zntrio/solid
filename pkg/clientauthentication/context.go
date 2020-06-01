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

	corev1 "zntr.io/solid/api/gen/go/oidc/core/v1"
)

type contextKey string

func (c contextKey) String() string {
	return "zntr.io/solid/pkg/clientauthentication/" + string(c)
}

var contextKeyClientAuth = contextKey("client")

// FromContext returns the client authentication bound to the context.
func FromContext(ctx context.Context) (*corev1.Client, bool) {
	client, ok := ctx.Value(contextKeyClientAuth).(*corev1.Client)
	return client, ok
}

// Inject client instance in context.
func Inject(ctx context.Context, client *corev1.Client) context.Context {
	return context.WithValue(ctx, contextKeyClientAuth, client)
}
