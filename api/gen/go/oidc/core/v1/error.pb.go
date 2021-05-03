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
// 	protoc-gen-go v1.26.0
// 	protoc        v3.15.8
// source: oidc/core/v1/error.proto

package corev1

import (
	reflect "reflect"
	sync "sync"

	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
	wrapperspb "google.golang.org/protobuf/types/known/wrapperspb"
)

const (
	// Verify that this generated code is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(20 - protoimpl.MinVersion)
	// Verify that runtime/protoimpl is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(protoimpl.MaxVersion - 20)
)

// https://www.rfc-editor.org/rfc/rfc6749.html#section-4.1.2.1
type Error struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// REQUIRED. Error code.
	Err string `protobuf:"bytes,1,opt,name=err,proto3" json:"err,omitempty"`
	// OPTIONAL. Human-readable ASCII encoded text description of the error.
	ErrorDescription string `protobuf:"bytes,2,opt,name=error_description,json=errorDescription,proto3" json:"error_description,omitempty"`
	// OPTIONAL. URI of a web page that includes additional information about the
	// error.
	ErrorUri *wrapperspb.StringValue `protobuf:"bytes,3,opt,name=error_uri,json=errorUri,proto3" json:"error_uri,omitempty"`
	// OAuth 2.0 state value. REQUIRED if the Authorization Request included the
	// state parameter. Set to the value received from the Client.
	State *wrapperspb.StringValue `protobuf:"bytes,4,opt,name=state,proto3" json:"state,omitempty"`
}

func (x *Error) Reset() {
	*x = Error{}
	if protoimpl.UnsafeEnabled {
		mi := &file_oidc_core_v1_error_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *Error) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Error) ProtoMessage() {}

func (x *Error) ProtoReflect() protoreflect.Message {
	mi := &file_oidc_core_v1_error_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Error.ProtoReflect.Descriptor instead.
func (*Error) Descriptor() ([]byte, []int) {
	return file_oidc_core_v1_error_proto_rawDescGZIP(), []int{0}
}

func (x *Error) GetErr() string {
	if x != nil {
		return x.Err
	}
	return ""
}

func (x *Error) GetErrorDescription() string {
	if x != nil {
		return x.ErrorDescription
	}
	return ""
}

func (x *Error) GetErrorUri() *wrapperspb.StringValue {
	if x != nil {
		return x.ErrorUri
	}
	return nil
}

func (x *Error) GetState() *wrapperspb.StringValue {
	if x != nil {
		return x.State
	}
	return nil
}

var File_oidc_core_v1_error_proto protoreflect.FileDescriptor

var file_oidc_core_v1_error_proto_rawDesc = []byte{
	0x0a, 0x18, 0x6f, 0x69, 0x64, 0x63, 0x2f, 0x63, 0x6f, 0x72, 0x65, 0x2f, 0x76, 0x31, 0x2f, 0x65,
	0x72, 0x72, 0x6f, 0x72, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12, 0x0c, 0x6f, 0x69, 0x64, 0x63,
	0x2e, 0x63, 0x6f, 0x72, 0x65, 0x2e, 0x76, 0x31, 0x1a, 0x1e, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65,
	0x2f, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2f, 0x77, 0x72, 0x61, 0x70, 0x70, 0x65,
	0x72, 0x73, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x22, 0xb5, 0x01, 0x0a, 0x05, 0x45, 0x72, 0x72,
	0x6f, 0x72, 0x12, 0x10, 0x0a, 0x03, 0x65, 0x72, 0x72, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52,
	0x03, 0x65, 0x72, 0x72, 0x12, 0x2b, 0x0a, 0x11, 0x65, 0x72, 0x72, 0x6f, 0x72, 0x5f, 0x64, 0x65,
	0x73, 0x63, 0x72, 0x69, 0x70, 0x74, 0x69, 0x6f, 0x6e, 0x18, 0x02, 0x20, 0x01, 0x28, 0x09, 0x52,
	0x10, 0x65, 0x72, 0x72, 0x6f, 0x72, 0x44, 0x65, 0x73, 0x63, 0x72, 0x69, 0x70, 0x74, 0x69, 0x6f,
	0x6e, 0x12, 0x39, 0x0a, 0x09, 0x65, 0x72, 0x72, 0x6f, 0x72, 0x5f, 0x75, 0x72, 0x69, 0x18, 0x03,
	0x20, 0x01, 0x28, 0x0b, 0x32, 0x1c, 0x2e, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2e, 0x70, 0x72,
	0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2e, 0x53, 0x74, 0x72, 0x69, 0x6e, 0x67, 0x56, 0x61, 0x6c,
	0x75, 0x65, 0x52, 0x08, 0x65, 0x72, 0x72, 0x6f, 0x72, 0x55, 0x72, 0x69, 0x12, 0x32, 0x0a, 0x05,
	0x73, 0x74, 0x61, 0x74, 0x65, 0x18, 0x04, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x1c, 0x2e, 0x67, 0x6f,
	0x6f, 0x67, 0x6c, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2e, 0x53, 0x74,
	0x72, 0x69, 0x6e, 0x67, 0x56, 0x61, 0x6c, 0x75, 0x65, 0x52, 0x05, 0x73, 0x74, 0x61, 0x74, 0x65,
	0x42, 0x15, 0x5a, 0x13, 0x6f, 0x69, 0x64, 0x63, 0x2f, 0x63, 0x6f, 0x72, 0x65, 0x2f, 0x76, 0x31,
	0x3b, 0x63, 0x6f, 0x72, 0x65, 0x76, 0x31, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_oidc_core_v1_error_proto_rawDescOnce sync.Once
	file_oidc_core_v1_error_proto_rawDescData = file_oidc_core_v1_error_proto_rawDesc
)

func file_oidc_core_v1_error_proto_rawDescGZIP() []byte {
	file_oidc_core_v1_error_proto_rawDescOnce.Do(func() {
		file_oidc_core_v1_error_proto_rawDescData = protoimpl.X.CompressGZIP(file_oidc_core_v1_error_proto_rawDescData)
	})
	return file_oidc_core_v1_error_proto_rawDescData
}

var (
	file_oidc_core_v1_error_proto_msgTypes = make([]protoimpl.MessageInfo, 1)
	file_oidc_core_v1_error_proto_goTypes  = []interface{}{
		(*Error)(nil),                  // 0: oidc.core.v1.Error
		(*wrapperspb.StringValue)(nil), // 1: google.protobuf.StringValue
	}
)

var file_oidc_core_v1_error_proto_depIdxs = []int32{
	1, // 0: oidc.core.v1.Error.error_uri:type_name -> google.protobuf.StringValue
	1, // 1: oidc.core.v1.Error.state:type_name -> google.protobuf.StringValue
	2, // [2:2] is the sub-list for method output_type
	2, // [2:2] is the sub-list for method input_type
	2, // [2:2] is the sub-list for extension type_name
	2, // [2:2] is the sub-list for extension extendee
	0, // [0:2] is the sub-list for field type_name
}

func init() { file_oidc_core_v1_error_proto_init() }
func file_oidc_core_v1_error_proto_init() {
	if File_oidc_core_v1_error_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_oidc_core_v1_error_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*Error); i {
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
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_oidc_core_v1_error_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   1,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_oidc_core_v1_error_proto_goTypes,
		DependencyIndexes: file_oidc_core_v1_error_proto_depIdxs,
		MessageInfos:      file_oidc_core_v1_error_proto_msgTypes,
	}.Build()
	File_oidc_core_v1_error_proto = out.File
	file_oidc_core_v1_error_proto_rawDesc = nil
	file_oidc_core_v1_error_proto_goTypes = nil
	file_oidc_core_v1_error_proto_depIdxs = nil
}
