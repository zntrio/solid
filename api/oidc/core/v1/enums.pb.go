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

// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.32.0
// 	protoc        (unknown)
// source: oidc/core/v1/enums.proto

package corev1

import (
	reflect "reflect"
	sync "sync"

	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
)

const (
	// Verify that this generated code is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(20 - protoimpl.MinVersion)
	// Verify that runtime/protoimpl is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(protoimpl.MaxVersion - 20)
)

// Display defines values to set how to displays the authentication and consent
// user interface pages to the End-User.
type Display int32

const (
	// Default value when nothing specificied.
	Display_DISPLAY_UNSPECIFIED Display = 0
	// Value to set as unknown.
	Display_DISPLAY_UNKNOWN Display = 1
	// The Authorization Server SHOULD display the authentication and consent UI
	// consistent with a full User Agent page view. If the display parameter is
	// not specified, this is the default display mode.
	Display_DISPLAY_PAGE Display = 2
	// The Authorization Server SHOULD display the authentication and consent UI
	// consistent with a popup User Agent window. The popup User Agent window
	// should be of an appropriate size for a login-focused dialog and should not
	// obscure the entire window that it is popping up over.
	Display_DISPLAY_POPUP Display = 3
	// The Authorization Server SHOULD display the authentication and consent UI
	// consistent with a device that leverages a touch interface.
	Display_DISPLAY_TOUCH Display = 4
	// The Authorization Server SHOULD display the authentication and consent UI
	// consistent with a "feature phone" type display.
	Display_DISPLAY_WAP Display = 5
)

// Enum value maps for Display.
var (
	Display_name = map[int32]string{
		0: "DISPLAY_UNSPECIFIED",
		1: "DISPLAY_UNKNOWN",
		2: "DISPLAY_PAGE",
		3: "DISPLAY_POPUP",
		4: "DISPLAY_TOUCH",
		5: "DISPLAY_WAP",
	}
	Display_value = map[string]int32{
		"DISPLAY_UNSPECIFIED": 0,
		"DISPLAY_UNKNOWN":     1,
		"DISPLAY_PAGE":        2,
		"DISPLAY_POPUP":       3,
		"DISPLAY_TOUCH":       4,
		"DISPLAY_WAP":         5,
	}
)

func (x Display) Enum() *Display {
	p := new(Display)
	*p = x
	return p
}

func (x Display) String() string {
	return protoimpl.X.EnumStringOf(x.Descriptor(), protoreflect.EnumNumber(x))
}

func (Display) Descriptor() protoreflect.EnumDescriptor {
	return file_oidc_core_v1_enums_proto_enumTypes[0].Descriptor()
}

func (Display) Type() protoreflect.EnumType {
	return &file_oidc_core_v1_enums_proto_enumTypes[0]
}

func (x Display) Number() protoreflect.EnumNumber {
	return protoreflect.EnumNumber(x)
}

// Deprecated: Use Display.Descriptor instead.
func (Display) EnumDescriptor() ([]byte, []int) {
	return file_oidc_core_v1_enums_proto_rawDescGZIP(), []int{0}
}

// Prompt defines values for required prompt actions.
type Prompt int32

const (
	// Default value when nothing specificied.
	Prompt_PROMPT_UNSPECIFIED Prompt = 0
	// Value to set as unknown.
	Prompt_PROMPT_UNKNOWN Prompt = 1
	// The Authorization Server MUST NOT display any authentication or consent
	// user interface pages. An error is returned if an End-User is not already
	// authenticated or the Client does not have pre-configured consent for the
	// requested Claims or does not fulfill other conditions for processing the
	// request. The error code will typically be login_required,
	// interaction_required, or another code defined in Section 3.1.2.6. This
	// can be used as a method to check for existing authentication and/or
	// consent.
	Prompt_PROMPT_NONE Prompt = 2
	// The Authorization Server SHOULD prompt the End-User for reauthentication.
	// If it cannot reauthenticate the End-User, it MUST return an error,
	// typically login_required.
	Prompt_PROMPT_LOGIN Prompt = 3
	// The Authorization Server SHOULD prompt the End-User for consent before
	// returning information to the Client. If it cannot obtain consent, it MUST
	// return an error, typically consent_required.
	Prompt_PROMPT_CONSENT Prompt = 4
	// The Authorization Server SHOULD prompt the End-User to select a user
	// account. This enables an End-User who has multiple accounts at the
	// Authorization Server to select amongst the multiple accounts that they
	// might have current sessions for. If it cannot obtain an account selection
	// choice made by the End-User, it MUST return an error, typically
	// account_selection_required.
	Prompt_PROMPT_SELECT_ACCOUNT Prompt = 5
)

// Enum value maps for Prompt.
var (
	Prompt_name = map[int32]string{
		0: "PROMPT_UNSPECIFIED",
		1: "PROMPT_UNKNOWN",
		2: "PROMPT_NONE",
		3: "PROMPT_LOGIN",
		4: "PROMPT_CONSENT",
		5: "PROMPT_SELECT_ACCOUNT",
	}
	Prompt_value = map[string]int32{
		"PROMPT_UNSPECIFIED":    0,
		"PROMPT_UNKNOWN":        1,
		"PROMPT_NONE":           2,
		"PROMPT_LOGIN":          3,
		"PROMPT_CONSENT":        4,
		"PROMPT_SELECT_ACCOUNT": 5,
	}
)

func (x Prompt) Enum() *Prompt {
	p := new(Prompt)
	*p = x
	return p
}

func (x Prompt) String() string {
	return protoimpl.X.EnumStringOf(x.Descriptor(), protoreflect.EnumNumber(x))
}

func (Prompt) Descriptor() protoreflect.EnumDescriptor {
	return file_oidc_core_v1_enums_proto_enumTypes[1].Descriptor()
}

func (Prompt) Type() protoreflect.EnumType {
	return &file_oidc_core_v1_enums_proto_enumTypes[1]
}

func (x Prompt) Number() protoreflect.EnumNumber {
	return protoreflect.EnumNumber(x)
}

// Deprecated: Use Prompt.Descriptor instead.
func (Prompt) EnumDescriptor() ([]byte, []int) {
	return file_oidc_core_v1_enums_proto_rawDescGZIP(), []int{1}
}

var File_oidc_core_v1_enums_proto protoreflect.FileDescriptor

var file_oidc_core_v1_enums_proto_rawDesc = []byte{
	0x0a, 0x18, 0x6f, 0x69, 0x64, 0x63, 0x2f, 0x63, 0x6f, 0x72, 0x65, 0x2f, 0x76, 0x31, 0x2f, 0x65,
	0x6e, 0x75, 0x6d, 0x73, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12, 0x0c, 0x6f, 0x69, 0x64, 0x63,
	0x2e, 0x63, 0x6f, 0x72, 0x65, 0x2e, 0x76, 0x31, 0x2a, 0x80, 0x01, 0x0a, 0x07, 0x44, 0x69, 0x73,
	0x70, 0x6c, 0x61, 0x79, 0x12, 0x17, 0x0a, 0x13, 0x44, 0x49, 0x53, 0x50, 0x4c, 0x41, 0x59, 0x5f,
	0x55, 0x4e, 0x53, 0x50, 0x45, 0x43, 0x49, 0x46, 0x49, 0x45, 0x44, 0x10, 0x00, 0x12, 0x13, 0x0a,
	0x0f, 0x44, 0x49, 0x53, 0x50, 0x4c, 0x41, 0x59, 0x5f, 0x55, 0x4e, 0x4b, 0x4e, 0x4f, 0x57, 0x4e,
	0x10, 0x01, 0x12, 0x10, 0x0a, 0x0c, 0x44, 0x49, 0x53, 0x50, 0x4c, 0x41, 0x59, 0x5f, 0x50, 0x41,
	0x47, 0x45, 0x10, 0x02, 0x12, 0x11, 0x0a, 0x0d, 0x44, 0x49, 0x53, 0x50, 0x4c, 0x41, 0x59, 0x5f,
	0x50, 0x4f, 0x50, 0x55, 0x50, 0x10, 0x03, 0x12, 0x11, 0x0a, 0x0d, 0x44, 0x49, 0x53, 0x50, 0x4c,
	0x41, 0x59, 0x5f, 0x54, 0x4f, 0x55, 0x43, 0x48, 0x10, 0x04, 0x12, 0x0f, 0x0a, 0x0b, 0x44, 0x49,
	0x53, 0x50, 0x4c, 0x41, 0x59, 0x5f, 0x57, 0x41, 0x50, 0x10, 0x05, 0x2a, 0x86, 0x01, 0x0a, 0x06,
	0x50, 0x72, 0x6f, 0x6d, 0x70, 0x74, 0x12, 0x16, 0x0a, 0x12, 0x50, 0x52, 0x4f, 0x4d, 0x50, 0x54,
	0x5f, 0x55, 0x4e, 0x53, 0x50, 0x45, 0x43, 0x49, 0x46, 0x49, 0x45, 0x44, 0x10, 0x00, 0x12, 0x12,
	0x0a, 0x0e, 0x50, 0x52, 0x4f, 0x4d, 0x50, 0x54, 0x5f, 0x55, 0x4e, 0x4b, 0x4e, 0x4f, 0x57, 0x4e,
	0x10, 0x01, 0x12, 0x0f, 0x0a, 0x0b, 0x50, 0x52, 0x4f, 0x4d, 0x50, 0x54, 0x5f, 0x4e, 0x4f, 0x4e,
	0x45, 0x10, 0x02, 0x12, 0x10, 0x0a, 0x0c, 0x50, 0x52, 0x4f, 0x4d, 0x50, 0x54, 0x5f, 0x4c, 0x4f,
	0x47, 0x49, 0x4e, 0x10, 0x03, 0x12, 0x12, 0x0a, 0x0e, 0x50, 0x52, 0x4f, 0x4d, 0x50, 0x54, 0x5f,
	0x43, 0x4f, 0x4e, 0x53, 0x45, 0x4e, 0x54, 0x10, 0x04, 0x12, 0x19, 0x0a, 0x15, 0x50, 0x52, 0x4f,
	0x4d, 0x50, 0x54, 0x5f, 0x53, 0x45, 0x4c, 0x45, 0x43, 0x54, 0x5f, 0x41, 0x43, 0x43, 0x4f, 0x55,
	0x4e, 0x54, 0x10, 0x05, 0x42, 0x97, 0x01, 0x0a, 0x10, 0x63, 0x6f, 0x6d, 0x2e, 0x6f, 0x69, 0x64,
	0x63, 0x2e, 0x63, 0x6f, 0x72, 0x65, 0x2e, 0x76, 0x31, 0x42, 0x0a, 0x45, 0x6e, 0x75, 0x6d, 0x73,
	0x50, 0x72, 0x6f, 0x74, 0x6f, 0x50, 0x01, 0x5a, 0x25, 0x7a, 0x6e, 0x74, 0x72, 0x2e, 0x69, 0x6f,
	0x2f, 0x73, 0x6f, 0x6c, 0x69, 0x64, 0x2f, 0x61, 0x70, 0x69, 0x2f, 0x6f, 0x69, 0x64, 0x63, 0x2f,
	0x63, 0x6f, 0x72, 0x65, 0x2f, 0x76, 0x31, 0x3b, 0x63, 0x6f, 0x72, 0x65, 0x76, 0x31, 0xa2, 0x02,
	0x03, 0x4f, 0x43, 0x58, 0xaa, 0x02, 0x0c, 0x4f, 0x69, 0x64, 0x63, 0x2e, 0x43, 0x6f, 0x72, 0x65,
	0x2e, 0x56, 0x31, 0xca, 0x02, 0x0c, 0x4f, 0x69, 0x64, 0x63, 0x5c, 0x43, 0x6f, 0x72, 0x65, 0x5c,
	0x56, 0x31, 0xe2, 0x02, 0x18, 0x4f, 0x69, 0x64, 0x63, 0x5c, 0x43, 0x6f, 0x72, 0x65, 0x5c, 0x56,
	0x31, 0x5c, 0x47, 0x50, 0x42, 0x4d, 0x65, 0x74, 0x61, 0x64, 0x61, 0x74, 0x61, 0xea, 0x02, 0x0e,
	0x4f, 0x69, 0x64, 0x63, 0x3a, 0x3a, 0x43, 0x6f, 0x72, 0x65, 0x3a, 0x3a, 0x56, 0x31, 0x62, 0x06,
	0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_oidc_core_v1_enums_proto_rawDescOnce sync.Once
	file_oidc_core_v1_enums_proto_rawDescData = file_oidc_core_v1_enums_proto_rawDesc
)

func file_oidc_core_v1_enums_proto_rawDescGZIP() []byte {
	file_oidc_core_v1_enums_proto_rawDescOnce.Do(func() {
		file_oidc_core_v1_enums_proto_rawDescData = protoimpl.X.CompressGZIP(file_oidc_core_v1_enums_proto_rawDescData)
	})
	return file_oidc_core_v1_enums_proto_rawDescData
}

var file_oidc_core_v1_enums_proto_enumTypes = make([]protoimpl.EnumInfo, 2)
var file_oidc_core_v1_enums_proto_goTypes = []interface{}{
	(Display)(0), // 0: oidc.core.v1.Display
	(Prompt)(0),  // 1: oidc.core.v1.Prompt
}
var file_oidc_core_v1_enums_proto_depIdxs = []int32{
	0, // [0:0] is the sub-list for method output_type
	0, // [0:0] is the sub-list for method input_type
	0, // [0:0] is the sub-list for extension type_name
	0, // [0:0] is the sub-list for extension extendee
	0, // [0:0] is the sub-list for field type_name
}

func init() { file_oidc_core_v1_enums_proto_init() }
func file_oidc_core_v1_enums_proto_init() {
	if File_oidc_core_v1_enums_proto != nil {
		return
	}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_oidc_core_v1_enums_proto_rawDesc,
			NumEnums:      2,
			NumMessages:   0,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_oidc_core_v1_enums_proto_goTypes,
		DependencyIndexes: file_oidc_core_v1_enums_proto_depIdxs,
		EnumInfos:         file_oidc_core_v1_enums_proto_enumTypes,
	}.Build()
	File_oidc_core_v1_enums_proto = out.File
	file_oidc_core_v1_enums_proto_rawDesc = nil
	file_oidc_core_v1_enums_proto_goTypes = nil
	file_oidc_core_v1_enums_proto_depIdxs = nil
}
