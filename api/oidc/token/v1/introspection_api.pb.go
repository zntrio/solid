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
// source: oidc/token/v1/introspection_api.proto

package tokenv1

import (
	reflect "reflect"
	sync "sync"

	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"

	v1 "zntr.io/solid/api/oidc/client/v1"
	v11 "zntr.io/solid/api/oidc/core/v1"
)

const (
	// Verify that this generated code is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(20 - protoimpl.MinVersion)
	// Verify that runtime/protoimpl is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(protoimpl.MaxVersion - 20)
)

// https://tools.ietf.org/html/rfc7662#section-2.1
type IntrospectRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// REQUIRED. Token issuer URL.
	Issuer string `protobuf:"bytes,1,opt,name=issuer,proto3" json:"issuer,omitempty"`
	// REQUIRED. Client that invoke the token introspection.
	Client *v1.Client `protobuf:"bytes,2,opt,name=client,proto3" json:"client,omitempty"`
	// REQUIRED.  The string value of the token.  For access tokens, this
	// is the "access_token" value returned from the token endpoint
	// defined in OAuth 2.0 [RFC6749], Section 5.1.  For refresh tokens,
	// this is the "refresh_token" value returned from the token endpoint
	// as defined in OAuth 2.0 [RFC6749], Section 5.1.  Other token types
	// are outside the scope of this specification.
	Token string `protobuf:"bytes,3,opt,name=token,proto3" json:"token,omitempty"`
	// OPTIONAL.  A hint about the type of the token submitted for
	// introspection.  The protected resource MAY pass this parameter to
	// help the authorization server optimize the token lookup.  If the
	// server is unable to locate the token using the given hint, it MUST
	// extend its search across all of its supported token types.  An
	// authorization server MAY ignore this parameter, particularly if it
	// is able to detect the token type automatically.  Values for this
	// field are defined in the "OAuth Token Type Hints" registry defined
	// in OAuth Token Revocation [RFC7009]
	TokenTypeHint *string `protobuf:"bytes,4,opt,name=token_type_hint,json=tokenTypeHint,proto3,oneof" json:"token_type_hint,omitempty"`
}

func (x *IntrospectRequest) Reset() {
	*x = IntrospectRequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_oidc_token_v1_introspection_api_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *IntrospectRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*IntrospectRequest) ProtoMessage() {}

func (x *IntrospectRequest) ProtoReflect() protoreflect.Message {
	mi := &file_oidc_token_v1_introspection_api_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use IntrospectRequest.ProtoReflect.Descriptor instead.
func (*IntrospectRequest) Descriptor() ([]byte, []int) {
	return file_oidc_token_v1_introspection_api_proto_rawDescGZIP(), []int{0}
}

func (x *IntrospectRequest) GetIssuer() string {
	if x != nil {
		return x.Issuer
	}
	return ""
}

func (x *IntrospectRequest) GetClient() *v1.Client {
	if x != nil {
		return x.Client
	}
	return nil
}

func (x *IntrospectRequest) GetToken() string {
	if x != nil {
		return x.Token
	}
	return ""
}

func (x *IntrospectRequest) GetTokenTypeHint() string {
	if x != nil && x.TokenTypeHint != nil {
		return *x.TokenTypeHint
	}
	return ""
}

// https://tools.ietf.org/html/rfc7662#section-2.2
type IntrospectResponse struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Error *v11.Error `protobuf:"bytes,1,opt,name=error,proto3" json:"error,omitempty"`
	// OPTIONAL. The matching token instance.
	Token *Token `protobuf:"bytes,2,opt,name=token,proto3" json:"token,omitempty"`
}

func (x *IntrospectResponse) Reset() {
	*x = IntrospectResponse{}
	if protoimpl.UnsafeEnabled {
		mi := &file_oidc_token_v1_introspection_api_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *IntrospectResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*IntrospectResponse) ProtoMessage() {}

func (x *IntrospectResponse) ProtoReflect() protoreflect.Message {
	mi := &file_oidc_token_v1_introspection_api_proto_msgTypes[1]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use IntrospectResponse.ProtoReflect.Descriptor instead.
func (*IntrospectResponse) Descriptor() ([]byte, []int) {
	return file_oidc_token_v1_introspection_api_proto_rawDescGZIP(), []int{1}
}

func (x *IntrospectResponse) GetError() *v11.Error {
	if x != nil {
		return x.Error
	}
	return nil
}

func (x *IntrospectResponse) GetToken() *Token {
	if x != nil {
		return x.Token
	}
	return nil
}

var File_oidc_token_v1_introspection_api_proto protoreflect.FileDescriptor

var file_oidc_token_v1_introspection_api_proto_rawDesc = []byte{
	0x0a, 0x25, 0x6f, 0x69, 0x64, 0x63, 0x2f, 0x74, 0x6f, 0x6b, 0x65, 0x6e, 0x2f, 0x76, 0x31, 0x2f,
	0x69, 0x6e, 0x74, 0x72, 0x6f, 0x73, 0x70, 0x65, 0x63, 0x74, 0x69, 0x6f, 0x6e, 0x5f, 0x61, 0x70,
	0x69, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12, 0x0d, 0x6f, 0x69, 0x64, 0x63, 0x2e, 0x74, 0x6f,
	0x6b, 0x65, 0x6e, 0x2e, 0x76, 0x31, 0x1a, 0x1b, 0x6f, 0x69, 0x64, 0x63, 0x2f, 0x63, 0x6c, 0x69,
	0x65, 0x6e, 0x74, 0x2f, 0x76, 0x31, 0x2f, 0x63, 0x6c, 0x69, 0x65, 0x6e, 0x74, 0x2e, 0x70, 0x72,
	0x6f, 0x74, 0x6f, 0x1a, 0x18, 0x6f, 0x69, 0x64, 0x63, 0x2f, 0x63, 0x6f, 0x72, 0x65, 0x2f, 0x76,
	0x31, 0x2f, 0x65, 0x72, 0x72, 0x6f, 0x72, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x19, 0x6f,
	0x69, 0x64, 0x63, 0x2f, 0x74, 0x6f, 0x6b, 0x65, 0x6e, 0x2f, 0x76, 0x31, 0x2f, 0x74, 0x6f, 0x6b,
	0x65, 0x6e, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x22, 0xb2, 0x01, 0x0a, 0x11, 0x49, 0x6e, 0x74,
	0x72, 0x6f, 0x73, 0x70, 0x65, 0x63, 0x74, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x12, 0x16,
	0x0a, 0x06, 0x69, 0x73, 0x73, 0x75, 0x65, 0x72, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x06,
	0x69, 0x73, 0x73, 0x75, 0x65, 0x72, 0x12, 0x2e, 0x0a, 0x06, 0x63, 0x6c, 0x69, 0x65, 0x6e, 0x74,
	0x18, 0x02, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x16, 0x2e, 0x6f, 0x69, 0x64, 0x63, 0x2e, 0x63, 0x6c,
	0x69, 0x65, 0x6e, 0x74, 0x2e, 0x76, 0x31, 0x2e, 0x43, 0x6c, 0x69, 0x65, 0x6e, 0x74, 0x52, 0x06,
	0x63, 0x6c, 0x69, 0x65, 0x6e, 0x74, 0x12, 0x14, 0x0a, 0x05, 0x74, 0x6f, 0x6b, 0x65, 0x6e, 0x18,
	0x03, 0x20, 0x01, 0x28, 0x09, 0x52, 0x05, 0x74, 0x6f, 0x6b, 0x65, 0x6e, 0x12, 0x2b, 0x0a, 0x0f,
	0x74, 0x6f, 0x6b, 0x65, 0x6e, 0x5f, 0x74, 0x79, 0x70, 0x65, 0x5f, 0x68, 0x69, 0x6e, 0x74, 0x18,
	0x04, 0x20, 0x01, 0x28, 0x09, 0x48, 0x00, 0x52, 0x0d, 0x74, 0x6f, 0x6b, 0x65, 0x6e, 0x54, 0x79,
	0x70, 0x65, 0x48, 0x69, 0x6e, 0x74, 0x88, 0x01, 0x01, 0x42, 0x12, 0x0a, 0x10, 0x5f, 0x74, 0x6f,
	0x6b, 0x65, 0x6e, 0x5f, 0x74, 0x79, 0x70, 0x65, 0x5f, 0x68, 0x69, 0x6e, 0x74, 0x22, 0x6b, 0x0a,
	0x12, 0x49, 0x6e, 0x74, 0x72, 0x6f, 0x73, 0x70, 0x65, 0x63, 0x74, 0x52, 0x65, 0x73, 0x70, 0x6f,
	0x6e, 0x73, 0x65, 0x12, 0x29, 0x0a, 0x05, 0x65, 0x72, 0x72, 0x6f, 0x72, 0x18, 0x01, 0x20, 0x01,
	0x28, 0x0b, 0x32, 0x13, 0x2e, 0x6f, 0x69, 0x64, 0x63, 0x2e, 0x63, 0x6f, 0x72, 0x65, 0x2e, 0x76,
	0x31, 0x2e, 0x45, 0x72, 0x72, 0x6f, 0x72, 0x52, 0x05, 0x65, 0x72, 0x72, 0x6f, 0x72, 0x12, 0x2a,
	0x0a, 0x05, 0x74, 0x6f, 0x6b, 0x65, 0x6e, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x14, 0x2e,
	0x6f, 0x69, 0x64, 0x63, 0x2e, 0x74, 0x6f, 0x6b, 0x65, 0x6e, 0x2e, 0x76, 0x31, 0x2e, 0x54, 0x6f,
	0x6b, 0x65, 0x6e, 0x52, 0x05, 0x74, 0x6f, 0x6b, 0x65, 0x6e, 0x32, 0x6b, 0x0a, 0x14, 0x49, 0x6e,
	0x74, 0x72, 0x6f, 0x73, 0x70, 0x65, 0x63, 0x74, 0x69, 0x6f, 0x6e, 0x53, 0x65, 0x72, 0x76, 0x69,
	0x63, 0x65, 0x12, 0x53, 0x0a, 0x0a, 0x49, 0x6e, 0x74, 0x72, 0x6f, 0x73, 0x70, 0x65, 0x63, 0x74,
	0x12, 0x20, 0x2e, 0x6f, 0x69, 0x64, 0x63, 0x2e, 0x74, 0x6f, 0x6b, 0x65, 0x6e, 0x2e, 0x76, 0x31,
	0x2e, 0x49, 0x6e, 0x74, 0x72, 0x6f, 0x73, 0x70, 0x65, 0x63, 0x74, 0x52, 0x65, 0x71, 0x75, 0x65,
	0x73, 0x74, 0x1a, 0x21, 0x2e, 0x6f, 0x69, 0x64, 0x63, 0x2e, 0x74, 0x6f, 0x6b, 0x65, 0x6e, 0x2e,
	0x76, 0x31, 0x2e, 0x49, 0x6e, 0x74, 0x72, 0x6f, 0x73, 0x70, 0x65, 0x63, 0x74, 0x52, 0x65, 0x73,
	0x70, 0x6f, 0x6e, 0x73, 0x65, 0x22, 0x00, 0x42, 0xa9, 0x01, 0x0a, 0x11, 0x63, 0x6f, 0x6d, 0x2e,
	0x6f, 0x69, 0x64, 0x63, 0x2e, 0x74, 0x6f, 0x6b, 0x65, 0x6e, 0x2e, 0x76, 0x31, 0x42, 0x15, 0x49,
	0x6e, 0x74, 0x72, 0x6f, 0x73, 0x70, 0x65, 0x63, 0x74, 0x69, 0x6f, 0x6e, 0x41, 0x70, 0x69, 0x50,
	0x72, 0x6f, 0x74, 0x6f, 0x50, 0x01, 0x5a, 0x27, 0x7a, 0x6e, 0x74, 0x72, 0x2e, 0x69, 0x6f, 0x2f,
	0x73, 0x6f, 0x6c, 0x69, 0x64, 0x2f, 0x61, 0x70, 0x69, 0x2f, 0x6f, 0x69, 0x64, 0x63, 0x2f, 0x74,
	0x6f, 0x6b, 0x65, 0x6e, 0x2f, 0x76, 0x31, 0x3b, 0x74, 0x6f, 0x6b, 0x65, 0x6e, 0x76, 0x31, 0xa2,
	0x02, 0x03, 0x4f, 0x54, 0x58, 0xaa, 0x02, 0x0d, 0x4f, 0x69, 0x64, 0x63, 0x2e, 0x54, 0x6f, 0x6b,
	0x65, 0x6e, 0x2e, 0x56, 0x31, 0xca, 0x02, 0x0d, 0x4f, 0x69, 0x64, 0x63, 0x5c, 0x54, 0x6f, 0x6b,
	0x65, 0x6e, 0x5c, 0x56, 0x31, 0xe2, 0x02, 0x19, 0x4f, 0x69, 0x64, 0x63, 0x5c, 0x54, 0x6f, 0x6b,
	0x65, 0x6e, 0x5c, 0x56, 0x31, 0x5c, 0x47, 0x50, 0x42, 0x4d, 0x65, 0x74, 0x61, 0x64, 0x61, 0x74,
	0x61, 0xea, 0x02, 0x0f, 0x4f, 0x69, 0x64, 0x63, 0x3a, 0x3a, 0x54, 0x6f, 0x6b, 0x65, 0x6e, 0x3a,
	0x3a, 0x56, 0x31, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_oidc_token_v1_introspection_api_proto_rawDescOnce sync.Once
	file_oidc_token_v1_introspection_api_proto_rawDescData = file_oidc_token_v1_introspection_api_proto_rawDesc
)

func file_oidc_token_v1_introspection_api_proto_rawDescGZIP() []byte {
	file_oidc_token_v1_introspection_api_proto_rawDescOnce.Do(func() {
		file_oidc_token_v1_introspection_api_proto_rawDescData = protoimpl.X.CompressGZIP(file_oidc_token_v1_introspection_api_proto_rawDescData)
	})
	return file_oidc_token_v1_introspection_api_proto_rawDescData
}

var file_oidc_token_v1_introspection_api_proto_msgTypes = make([]protoimpl.MessageInfo, 2)
var file_oidc_token_v1_introspection_api_proto_goTypes = []interface{}{
	(*IntrospectRequest)(nil),  // 0: oidc.token.v1.IntrospectRequest
	(*IntrospectResponse)(nil), // 1: oidc.token.v1.IntrospectResponse
	(*v1.Client)(nil),          // 2: oidc.client.v1.Client
	(*v11.Error)(nil),          // 3: oidc.core.v1.Error
	(*Token)(nil),              // 4: oidc.token.v1.Token
}
var file_oidc_token_v1_introspection_api_proto_depIdxs = []int32{
	2, // 0: oidc.token.v1.IntrospectRequest.client:type_name -> oidc.client.v1.Client
	3, // 1: oidc.token.v1.IntrospectResponse.error:type_name -> oidc.core.v1.Error
	4, // 2: oidc.token.v1.IntrospectResponse.token:type_name -> oidc.token.v1.Token
	0, // 3: oidc.token.v1.IntrospectionService.Introspect:input_type -> oidc.token.v1.IntrospectRequest
	1, // 4: oidc.token.v1.IntrospectionService.Introspect:output_type -> oidc.token.v1.IntrospectResponse
	4, // [4:5] is the sub-list for method output_type
	3, // [3:4] is the sub-list for method input_type
	3, // [3:3] is the sub-list for extension type_name
	3, // [3:3] is the sub-list for extension extendee
	0, // [0:3] is the sub-list for field type_name
}

func init() { file_oidc_token_v1_introspection_api_proto_init() }
func file_oidc_token_v1_introspection_api_proto_init() {
	if File_oidc_token_v1_introspection_api_proto != nil {
		return
	}
	file_oidc_token_v1_token_proto_init()
	if !protoimpl.UnsafeEnabled {
		file_oidc_token_v1_introspection_api_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*IntrospectRequest); i {
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
		file_oidc_token_v1_introspection_api_proto_msgTypes[1].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*IntrospectResponse); i {
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
	file_oidc_token_v1_introspection_api_proto_msgTypes[0].OneofWrappers = []interface{}{}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_oidc_token_v1_introspection_api_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   2,
			NumExtensions: 0,
			NumServices:   1,
		},
		GoTypes:           file_oidc_token_v1_introspection_api_proto_goTypes,
		DependencyIndexes: file_oidc_token_v1_introspection_api_proto_depIdxs,
		MessageInfos:      file_oidc_token_v1_introspection_api_proto_msgTypes,
	}.Build()
	File_oidc_token_v1_introspection_api_proto = out.File
	file_oidc_token_v1_introspection_api_proto_rawDesc = nil
	file_oidc_token_v1_introspection_api_proto_goTypes = nil
	file_oidc_token_v1_introspection_api_proto_depIdxs = nil
}
