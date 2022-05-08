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
// 	protoc-gen-go v1.27.1
// 	protoc        v3.17.3
// source: oidc/core/v1/revocation_api.proto

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

// https://tools.ietf.org/html/rfc7009#section-2.1
type TokenRevocationRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// REQUIRED. Client that invoke the token revocation.
	Client *Client `protobuf:"bytes,1,opt,name=client,proto3" json:"client,omitempty"`
	// REQUIRED.  The token that the client wants to get revoked.
	Token string `protobuf:"bytes,2,opt,name=token,proto3" json:"token,omitempty"`
	// OPTIONAL.  A hint about the type of the token
	// submitted for revocation.  Clients MAY pass this parameter in
	// order to help the authorization server to optimize the token
	// lookup.  If the server is unable to locate the token using
	// the given hint, it MUST extend its search across all of its
	// supported token types.  An authorization server MAY ignore
	// this parameter, particularly if it is able to detect the
	// token type automatically.  This specification defines two
	// such values:
	TokenTypeHint *string `protobuf:"bytes,3,opt,name=token_type_hint,json=tokenTypeHint,proto3,oneof" json:"token_type_hint,omitempty"`
}

func (x *TokenRevocationRequest) Reset() {
	*x = TokenRevocationRequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_oidc_core_v1_revocation_api_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *TokenRevocationRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*TokenRevocationRequest) ProtoMessage() {}

func (x *TokenRevocationRequest) ProtoReflect() protoreflect.Message {
	mi := &file_oidc_core_v1_revocation_api_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use TokenRevocationRequest.ProtoReflect.Descriptor instead.
func (*TokenRevocationRequest) Descriptor() ([]byte, []int) {
	return file_oidc_core_v1_revocation_api_proto_rawDescGZIP(), []int{0}
}

func (x *TokenRevocationRequest) GetClient() *Client {
	if x != nil {
		return x.Client
	}
	return nil
}

func (x *TokenRevocationRequest) GetToken() string {
	if x != nil {
		return x.Token
	}
	return ""
}

func (x *TokenRevocationRequest) GetTokenTypeHint() string {
	if x != nil && x.TokenTypeHint != nil {
		return *x.TokenTypeHint
	}
	return ""
}

type TokenRevocationResponse struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Error *Error `protobuf:"bytes,1,opt,name=error,proto3" json:"error,omitempty"`
}

func (x *TokenRevocationResponse) Reset() {
	*x = TokenRevocationResponse{}
	if protoimpl.UnsafeEnabled {
		mi := &file_oidc_core_v1_revocation_api_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *TokenRevocationResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*TokenRevocationResponse) ProtoMessage() {}

func (x *TokenRevocationResponse) ProtoReflect() protoreflect.Message {
	mi := &file_oidc_core_v1_revocation_api_proto_msgTypes[1]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use TokenRevocationResponse.ProtoReflect.Descriptor instead.
func (*TokenRevocationResponse) Descriptor() ([]byte, []int) {
	return file_oidc_core_v1_revocation_api_proto_rawDescGZIP(), []int{1}
}

func (x *TokenRevocationResponse) GetError() *Error {
	if x != nil {
		return x.Error
	}
	return nil
}

var File_oidc_core_v1_revocation_api_proto protoreflect.FileDescriptor

var file_oidc_core_v1_revocation_api_proto_rawDesc = []byte{
	0x0a, 0x21, 0x6f, 0x69, 0x64, 0x63, 0x2f, 0x63, 0x6f, 0x72, 0x65, 0x2f, 0x76, 0x31, 0x2f, 0x72,
	0x65, 0x76, 0x6f, 0x63, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x5f, 0x61, 0x70, 0x69, 0x2e, 0x70, 0x72,
	0x6f, 0x74, 0x6f, 0x12, 0x0c, 0x6f, 0x69, 0x64, 0x63, 0x2e, 0x63, 0x6f, 0x72, 0x65, 0x2e, 0x76,
	0x31, 0x1a, 0x19, 0x6f, 0x69, 0x64, 0x63, 0x2f, 0x63, 0x6f, 0x72, 0x65, 0x2f, 0x76, 0x31, 0x2f,
	0x63, 0x6c, 0x69, 0x65, 0x6e, 0x74, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x18, 0x6f, 0x69,
	0x64, 0x63, 0x2f, 0x63, 0x6f, 0x72, 0x65, 0x2f, 0x76, 0x31, 0x2f, 0x65, 0x72, 0x72, 0x6f, 0x72,
	0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x22, 0x9d, 0x01, 0x0a, 0x16, 0x54, 0x6f, 0x6b, 0x65, 0x6e,
	0x52, 0x65, 0x76, 0x6f, 0x63, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73,
	0x74, 0x12, 0x2c, 0x0a, 0x06, 0x63, 0x6c, 0x69, 0x65, 0x6e, 0x74, 0x18, 0x01, 0x20, 0x01, 0x28,
	0x0b, 0x32, 0x14, 0x2e, 0x6f, 0x69, 0x64, 0x63, 0x2e, 0x63, 0x6f, 0x72, 0x65, 0x2e, 0x76, 0x31,
	0x2e, 0x43, 0x6c, 0x69, 0x65, 0x6e, 0x74, 0x52, 0x06, 0x63, 0x6c, 0x69, 0x65, 0x6e, 0x74, 0x12,
	0x14, 0x0a, 0x05, 0x74, 0x6f, 0x6b, 0x65, 0x6e, 0x18, 0x02, 0x20, 0x01, 0x28, 0x09, 0x52, 0x05,
	0x74, 0x6f, 0x6b, 0x65, 0x6e, 0x12, 0x2b, 0x0a, 0x0f, 0x74, 0x6f, 0x6b, 0x65, 0x6e, 0x5f, 0x74,
	0x79, 0x70, 0x65, 0x5f, 0x68, 0x69, 0x6e, 0x74, 0x18, 0x03, 0x20, 0x01, 0x28, 0x09, 0x48, 0x00,
	0x52, 0x0d, 0x74, 0x6f, 0x6b, 0x65, 0x6e, 0x54, 0x79, 0x70, 0x65, 0x48, 0x69, 0x6e, 0x74, 0x88,
	0x01, 0x01, 0x42, 0x12, 0x0a, 0x10, 0x5f, 0x74, 0x6f, 0x6b, 0x65, 0x6e, 0x5f, 0x74, 0x79, 0x70,
	0x65, 0x5f, 0x68, 0x69, 0x6e, 0x74, 0x22, 0x44, 0x0a, 0x17, 0x54, 0x6f, 0x6b, 0x65, 0x6e, 0x52,
	0x65, 0x76, 0x6f, 0x63, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73,
	0x65, 0x12, 0x29, 0x0a, 0x05, 0x65, 0x72, 0x72, 0x6f, 0x72, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0b,
	0x32, 0x13, 0x2e, 0x6f, 0x69, 0x64, 0x63, 0x2e, 0x63, 0x6f, 0x72, 0x65, 0x2e, 0x76, 0x31, 0x2e,
	0x45, 0x72, 0x72, 0x6f, 0x72, 0x52, 0x05, 0x65, 0x72, 0x72, 0x6f, 0x72, 0x32, 0x71, 0x0a, 0x11,
	0x54, 0x6f, 0x6b, 0x65, 0x6e, 0x52, 0x65, 0x76, 0x6f, 0x63, 0x61, 0x74, 0x6f, 0x6e, 0x41, 0x50,
	0x49, 0x12, 0x5c, 0x0a, 0x0b, 0x52, 0x65, 0x76, 0x6f, 0x6b, 0x65, 0x54, 0x6f, 0x6b, 0x65, 0x6e,
	0x12, 0x24, 0x2e, 0x6f, 0x69, 0x64, 0x63, 0x2e, 0x63, 0x6f, 0x72, 0x65, 0x2e, 0x76, 0x31, 0x2e,
	0x54, 0x6f, 0x6b, 0x65, 0x6e, 0x52, 0x65, 0x76, 0x6f, 0x63, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x52,
	0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x1a, 0x25, 0x2e, 0x6f, 0x69, 0x64, 0x63, 0x2e, 0x63, 0x6f,
	0x72, 0x65, 0x2e, 0x76, 0x31, 0x2e, 0x54, 0x6f, 0x6b, 0x65, 0x6e, 0x52, 0x65, 0x76, 0x6f, 0x63,
	0x61, 0x74, 0x69, 0x6f, 0x6e, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x22, 0x00, 0x42,
	0x15, 0x5a, 0x13, 0x6f, 0x69, 0x64, 0x63, 0x2f, 0x63, 0x6f, 0x72, 0x65, 0x2f, 0x76, 0x31, 0x3b,
	0x63, 0x6f, 0x72, 0x65, 0x76, 0x31, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_oidc_core_v1_revocation_api_proto_rawDescOnce sync.Once
	file_oidc_core_v1_revocation_api_proto_rawDescData = file_oidc_core_v1_revocation_api_proto_rawDesc
)

func file_oidc_core_v1_revocation_api_proto_rawDescGZIP() []byte {
	file_oidc_core_v1_revocation_api_proto_rawDescOnce.Do(func() {
		file_oidc_core_v1_revocation_api_proto_rawDescData = protoimpl.X.CompressGZIP(file_oidc_core_v1_revocation_api_proto_rawDescData)
	})
	return file_oidc_core_v1_revocation_api_proto_rawDescData
}

var (
	file_oidc_core_v1_revocation_api_proto_msgTypes = make([]protoimpl.MessageInfo, 2)
	file_oidc_core_v1_revocation_api_proto_goTypes  = []any{
		(*TokenRevocationRequest)(nil),  // 0: oidc.core.v1.TokenRevocationRequest
		(*TokenRevocationResponse)(nil), // 1: oidc.core.v1.TokenRevocationResponse
		(*Client)(nil),                  // 2: oidc.core.v1.Client
		(*Error)(nil),                   // 3: oidc.core.v1.Error
	}
)

var file_oidc_core_v1_revocation_api_proto_depIdxs = []int32{
	2, // 0: oidc.core.v1.TokenRevocationRequest.client:type_name -> oidc.core.v1.Client
	3, // 1: oidc.core.v1.TokenRevocationResponse.error:type_name -> oidc.core.v1.Error
	0, // 2: oidc.core.v1.TokenRevocatonAPI.RevokeToken:input_type -> oidc.core.v1.TokenRevocationRequest
	1, // 3: oidc.core.v1.TokenRevocatonAPI.RevokeToken:output_type -> oidc.core.v1.TokenRevocationResponse
	3, // [3:4] is the sub-list for method output_type
	2, // [2:3] is the sub-list for method input_type
	2, // [2:2] is the sub-list for extension type_name
	2, // [2:2] is the sub-list for extension extendee
	0, // [0:2] is the sub-list for field type_name
}

func init() { file_oidc_core_v1_revocation_api_proto_init() }
func file_oidc_core_v1_revocation_api_proto_init() {
	if File_oidc_core_v1_revocation_api_proto != nil {
		return
	}
	file_oidc_core_v1_client_proto_init()
	file_oidc_core_v1_error_proto_init()
	if !protoimpl.UnsafeEnabled {
		file_oidc_core_v1_revocation_api_proto_msgTypes[0].Exporter = func(v any, i int) any {
			switch v := v.(*TokenRevocationRequest); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_oidc_core_v1_revocation_api_proto_msgTypes[1].Exporter = func(v any, i int) any {
			switch v := v.(*TokenRevocationResponse); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
	}
	file_oidc_core_v1_revocation_api_proto_msgTypes[0].OneofWrappers = []any{}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_oidc_core_v1_revocation_api_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   2,
			NumExtensions: 0,
			NumServices:   1,
		},
		GoTypes:           file_oidc_core_v1_revocation_api_proto_goTypes,
		DependencyIndexes: file_oidc_core_v1_revocation_api_proto_depIdxs,
		MessageInfos:      file_oidc_core_v1_revocation_api_proto_msgTypes,
	}.Build()
	File_oidc_core_v1_revocation_api_proto = out.File
	file_oidc_core_v1_revocation_api_proto_rawDesc = nil
	file_oidc_core_v1_revocation_api_proto_goTypes = nil
	file_oidc_core_v1_revocation_api_proto_depIdxs = nil
}
