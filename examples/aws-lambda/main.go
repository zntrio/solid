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

package main

import (
	"context"

	corev1 "zntr.io/solid/api/gen/go/oidc/core/v1"
	"zntr.io/solid/examples/storage/inmemory"
	"zntr.io/solid/pkg/authorizationserver"
	"zntr.io/solid/pkg/authorizationserver/features/oidc"

	"github.com/aws/aws-lambda-go/lambda"
)

// Handler initializes a lambda handler using given authorization server implementation.
// https://kennbrodhagen.net/2015/12/06/how-to-create-a-request-object-for-your-lambda-event-from-api-gateway/
func Handler(as authorizationserver.AuthorizationServer) func(context.Context, *corev1.AuthorizationRequest) (*corev1.AuthorizationResponse, error) {
	return func(ctx context.Context, req *corev1.AuthorizationRequest) (*corev1.AuthorizationResponse, error) {
		// Send an authentication request
		res, err := as.Do(ctx, req)
		return res.(*corev1.AuthorizationResponse), err
	}
}

func main() {
	ctx := context.Background()

	// Prepare the authorization server
	as := authorizationserver.New(ctx,
		"http://localhost", // Issuer
		authorizationserver.ClientReader(inmemory.Clients()),
		authorizationserver.AuthorizationRequestManager(inmemory.AuthorizationRequests()),
		authorizationserver.SessionManager(inmemory.Sessions()),
	)

	// Enable Core OIDC features
	as.Enable(oidc.Core())

	// Start the lambda
	lambda.Start(Handler(as))
}
