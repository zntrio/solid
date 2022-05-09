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

package generator

import (
	"context"
	"testing"
)

func Test_deviceCodeGenerator_Generate(t *testing.T) {
	c := DefaultDeviceCode()
	got, err := c.Generate(context.Background(), "http://test.example.com")
	if err != nil {
		t.Fatalf("unexpected error occurs, got %v", err)
	}
	if len(got) != DefaultDeviceCodeLen {
		t.Errorf("generated value has not the required length (%d)", DefaultDeviceCodeLen)
	}
}
