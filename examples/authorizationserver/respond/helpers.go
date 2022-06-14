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

package respond

import (
	"fmt"
	"net/http"

	jsoniter "github.com/json-iterator/go"

	corev1 "zntr.io/solid/api/oidc/core/v1"
)

func WithError(w http.ResponseWriter, r *http.Request, code int, err *corev1.Error) {
	json := jsoniter.ConfigCompatibleWithStandardLibrary

	// Marshal response as json
	body, _ := json.Marshal(err)

	// Set content type header
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("WWW-Authenticate", fmt.Sprintf(`Bearer realm="%s", error="%s", error_description="%s"`, r.URL.Host, err.Err, err.ErrorDescription))

	// Write status
	w.WriteHeader(code)

	// Write response
	w.Write(body)
}

// JSON serialize the data with matching requested encoding
func WithJSON(w http.ResponseWriter, r *http.Request, code int, data interface{}) {
	json := jsoniter.ConfigCompatibleWithStandardLibrary

	// Marshal response as json
	body, _ := json.Marshal(data)

	// Set content type header
	w.Header().Set("Content-Type", "application/json; charset=utf-8")

	// Write status
	w.WriteHeader(code)

	// Write response
	w.Write(body)
}
