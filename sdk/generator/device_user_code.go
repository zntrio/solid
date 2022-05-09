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
	"fmt"

	"github.com/dchest/uniuri"
)

const (
	// DefaultAlphaDeviceCodeLen defines default device code length.
	DefaultAlphaDeviceCodeLen = 8
	// DefaultNumDeviceCodeLen defines default device code length
	DefaultNumDeviceCodeLen = 9
)

var (
	// DefaultAlphaDeviceCodeCharset defines default device_code character set.
	// https://tools.ietf.org/html/rfc8628#section-6.1
	DefaultAlphaDeviceCodeCharset = []byte("BCDFGHJKLMNPQRSTVWXZ")
	// DefaultNumDeviceCodeCharset defines default device_code character set.
	DefaultNumDeviceCodeCharset = []byte("0123456789")
)

// -----------------------------------------------------------------------------

// DefaultDeviceUserCode returns the default device code generator.
func DefaultDeviceUserCode() DeviceUserCode {
	return &deviceCodeAlphaGenerator{}
}

type deviceCodeAlphaGenerator struct{}

func (c *deviceCodeAlphaGenerator) Generate(_ context.Context, _ string) (string, error) {
	code := uniuri.NewLenChars(DefaultAlphaDeviceCodeLen, DefaultAlphaDeviceCodeCharset)
	return fmt.Sprintf("%s-%s", code[:4], code[4:]), nil
}

// -----------------------------------------------------------------------------

// DefaultNumDeviceUserCode returns the default device code generator.
func DefaultNumDeviceUserCode() DeviceUserCode {
	return &deviceCodeNumGenerator{}
}

type deviceCodeNumGenerator struct{}

func (c *deviceCodeNumGenerator) Generate(_ context.Context, _ string) (string, error) {
	code := uniuri.NewLenChars(DefaultNumDeviceCodeLen, DefaultNumDeviceCodeCharset)
	return fmt.Sprintf("%s-%s-%s", code[:3], code[3:6], code[6:]), nil
}
