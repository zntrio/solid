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

package types

import (
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestStringArray_Contains(t *testing.T) {
	tests := []struct {
		name string
		s    StringArray
		args string
		want bool
	}{
		{
			name: "nil",
			s:    nil,
			want: false,
		},
		{
			name: "empty",
			s:    []string{},
			want: false,
		},
		{
			name: "empty / blank",
			s:    []string{},
			args: "",
			want: false,
		},
		{
			name: "not empty / blank",
			s:    []string{""},
			args: "",
			want: true,
		},
		{
			name: "not empty / same case",
			s:    []string{"azerty"},
			args: "azerty",
			want: true,
		},
		{
			name: "not empty / not same case",
			s:    []string{"azerty"},
			args: "AzErTy",
			want: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.s.Contains(tt.args); got != tt.want {
				t.Errorf("StringArray.Contains() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestStringArray_AddIfNotContains(t *testing.T) {
	tests := []struct {
		name string
		s    StringArray
		args string
		want StringArray
	}{
		{
			name: "contains",
			s:    []string{"1", "2", "3"},
			args: "3",
			want: []string{"1", "2", "3"},
		},
		{
			name: "not contains",
			s:    []string{"1", "2", "3"},
			args: "4",
			want: []string{"1", "2", "3", "4"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.s.AddIfNotContains(tt.args)
			if !cmp.Equal(tt.s, tt.want) {
				t.Errorf("AddIfNotContains() = %v, want %v", tt.s, tt.want)
			}
		})
	}
}

func TestStringArray_Remove(t *testing.T) {
	tests := []struct {
		name string
		s    StringArray
		args string
		want StringArray
	}{
		{
			name: "contains",
			s:    []string{"1", "2", "3"},
			args: "3",
			want: []string{"1", "2"},
		},
		{
			name: "not contains",
			s:    []string{"1", "2", "3"},
			args: "4",
			want: []string{"1", "2", "3"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.s.Remove(tt.args)
			if !cmp.Equal(tt.s, tt.want) {
				t.Errorf("Remove() = %v, want %v", tt.s, tt.want)
			}
		})
	}
}

func TestStringArray_HasOneOf(t *testing.T) {
	type args struct {
		items []string
	}
	tests := []struct {
		name string
		s    StringArray
		args []string
		want bool
	}{
		{
			name: "empty",
			want: false,
			s:    []string{},
			args: []string{},
		},
		{
			name: "empty / not empty",
			want: false,
			s:    []string{},
			args: []string{""},
		},
		{
			name: "not empty / empty",
			want: false,
			s:    []string{},
			args: []string{""},
		},
		{
			name: "contains",
			want: true,
			s:    []string{"1", "2", "3"},
			args: []string{"1"},
		},
		{
			name: "partial contains",
			want: true,
			s:    []string{"1", "2", "3"},
			args: []string{"1", "4"},
		},
		{
			name: "not contains at all",
			want: false,
			s:    []string{"1", "2", "3"},
			args: []string{"4"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.s.HasOneOf(tt.args...); got != tt.want {
				t.Errorf("StringArray.HasOneOf() = %v, want %v", got, tt.want)
			}
		})
	}
}
