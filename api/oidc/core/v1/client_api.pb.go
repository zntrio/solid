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
// 	protoc-gen-go v1.28.0
// 	protoc        v3.19.4
// source: oidc/core/v1/client_api.proto

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

type ClientAuthenticationRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	ClientId            *string `protobuf:"bytes,1,opt,name=client_id,json=clientId,proto3,oneof" json:"client_id,omitempty"`
	ClientSecret        *string `protobuf:"bytes,2,opt,name=client_secret,json=clientSecret,proto3,oneof" json:"client_secret,omitempty"`
	ClientAssertionType *string `protobuf:"bytes,3,opt,name=client_assertion_type,json=clientAssertionType,proto3,oneof" json:"client_assertion_type,omitempty"`
	ClientAssertion     *string `protobuf:"bytes,4,opt,name=client_assertion,json=clientAssertion,proto3,oneof" json:"client_assertion,omitempty"`
}

func (x *ClientAuthenticationRequest) Reset() {
	*x = ClientAuthenticationRequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_oidc_core_v1_client_api_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *ClientAuthenticationRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*ClientAuthenticationRequest) ProtoMessage() {}

func (x *ClientAuthenticationRequest) ProtoReflect() protoreflect.Message {
	mi := &file_oidc_core_v1_client_api_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use ClientAuthenticationRequest.ProtoReflect.Descriptor instead.
func (*ClientAuthenticationRequest) Descriptor() ([]byte, []int) {
	return file_oidc_core_v1_client_api_proto_rawDescGZIP(), []int{0}
}

func (x *ClientAuthenticationRequest) GetClientId() string {
	if x != nil && x.ClientId != nil {
		return *x.ClientId
	}
	return ""
}

func (x *ClientAuthenticationRequest) GetClientSecret() string {
	if x != nil && x.ClientSecret != nil {
		return *x.ClientSecret
	}
	return ""
}

func (x *ClientAuthenticationRequest) GetClientAssertionType() string {
	if x != nil && x.ClientAssertionType != nil {
		return *x.ClientAssertionType
	}
	return ""
}

func (x *ClientAuthenticationRequest) GetClientAssertion() string {
	if x != nil && x.ClientAssertion != nil {
		return *x.ClientAssertion
	}
	return ""
}

type ClientAuthenticationResponse struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Error  *Error  `protobuf:"bytes,1,opt,name=error,proto3" json:"error,omitempty"`
	Client *Client `protobuf:"bytes,2,opt,name=client,proto3" json:"client,omitempty"`
}

func (x *ClientAuthenticationResponse) Reset() {
	*x = ClientAuthenticationResponse{}
	if protoimpl.UnsafeEnabled {
		mi := &file_oidc_core_v1_client_api_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *ClientAuthenticationResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*ClientAuthenticationResponse) ProtoMessage() {}

func (x *ClientAuthenticationResponse) ProtoReflect() protoreflect.Message {
	mi := &file_oidc_core_v1_client_api_proto_msgTypes[1]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use ClientAuthenticationResponse.ProtoReflect.Descriptor instead.
func (*ClientAuthenticationResponse) Descriptor() ([]byte, []int) {
	return file_oidc_core_v1_client_api_proto_rawDescGZIP(), []int{1}
}

func (x *ClientAuthenticationResponse) GetError() *Error {
	if x != nil {
		return x.Error
	}
	return nil
}

func (x *ClientAuthenticationResponse) GetClient() *Client {
	if x != nil {
		return x.Client
	}
	return nil
}

// https://tools.ietf.org/html/rfc7591#section-2
type ClientRegistrationRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Metadata *ClientMeta `protobuf:"bytes,1,opt,name=metadata,proto3" json:"metadata,omitempty"`
}

func (x *ClientRegistrationRequest) Reset() {
	*x = ClientRegistrationRequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_oidc_core_v1_client_api_proto_msgTypes[2]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *ClientRegistrationRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*ClientRegistrationRequest) ProtoMessage() {}

func (x *ClientRegistrationRequest) ProtoReflect() protoreflect.Message {
	mi := &file_oidc_core_v1_client_api_proto_msgTypes[2]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use ClientRegistrationRequest.ProtoReflect.Descriptor instead.
func (*ClientRegistrationRequest) Descriptor() ([]byte, []int) {
	return file_oidc_core_v1_client_api_proto_rawDescGZIP(), []int{2}
}

func (x *ClientRegistrationRequest) GetMetadata() *ClientMeta {
	if x != nil {
		return x.Metadata
	}
	return nil
}

type ClientRegistrationResponse struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Error  *Error  `protobuf:"bytes,1,opt,name=error,proto3" json:"error,omitempty"`
	Client *Client `protobuf:"bytes,2,opt,name=client,proto3" json:"client,omitempty"`
}

func (x *ClientRegistrationResponse) Reset() {
	*x = ClientRegistrationResponse{}
	if protoimpl.UnsafeEnabled {
		mi := &file_oidc_core_v1_client_api_proto_msgTypes[3]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *ClientRegistrationResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*ClientRegistrationResponse) ProtoMessage() {}

func (x *ClientRegistrationResponse) ProtoReflect() protoreflect.Message {
	mi := &file_oidc_core_v1_client_api_proto_msgTypes[3]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use ClientRegistrationResponse.ProtoReflect.Descriptor instead.
func (*ClientRegistrationResponse) Descriptor() ([]byte, []int) {
	return file_oidc_core_v1_client_api_proto_rawDescGZIP(), []int{3}
}

func (x *ClientRegistrationResponse) GetError() *Error {
	if x != nil {
		return x.Error
	}
	return nil
}

func (x *ClientRegistrationResponse) GetClient() *Client {
	if x != nil {
		return x.Client
	}
	return nil
}

var File_oidc_core_v1_client_api_proto protoreflect.FileDescriptor

var file_oidc_core_v1_client_api_proto_rawDesc = []byte{
	0x0a, 0x1d, 0x6f, 0x69, 0x64, 0x63, 0x2f, 0x63, 0x6f, 0x72, 0x65, 0x2f, 0x76, 0x31, 0x2f, 0x63,
	0x6c, 0x69, 0x65, 0x6e, 0x74, 0x5f, 0x61, 0x70, 0x69, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12,
	0x0c, 0x6f, 0x69, 0x64, 0x63, 0x2e, 0x63, 0x6f, 0x72, 0x65, 0x2e, 0x76, 0x31, 0x1a, 0x19, 0x6f,
	0x69, 0x64, 0x63, 0x2f, 0x63, 0x6f, 0x72, 0x65, 0x2f, 0x76, 0x31, 0x2f, 0x63, 0x6c, 0x69, 0x65,
	0x6e, 0x74, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x18, 0x6f, 0x69, 0x64, 0x63, 0x2f, 0x63,
	0x6f, 0x72, 0x65, 0x2f, 0x76, 0x31, 0x2f, 0x65, 0x72, 0x72, 0x6f, 0x72, 0x2e, 0x70, 0x72, 0x6f,
	0x74, 0x6f, 0x22, 0xa1, 0x02, 0x0a, 0x1b, 0x43, 0x6c, 0x69, 0x65, 0x6e, 0x74, 0x41, 0x75, 0x74,
	0x68, 0x65, 0x6e, 0x74, 0x69, 0x63, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x52, 0x65, 0x71, 0x75, 0x65,
	0x73, 0x74, 0x12, 0x20, 0x0a, 0x09, 0x63, 0x6c, 0x69, 0x65, 0x6e, 0x74, 0x5f, 0x69, 0x64, 0x18,
	0x01, 0x20, 0x01, 0x28, 0x09, 0x48, 0x00, 0x52, 0x08, 0x63, 0x6c, 0x69, 0x65, 0x6e, 0x74, 0x49,
	0x64, 0x88, 0x01, 0x01, 0x12, 0x28, 0x0a, 0x0d, 0x63, 0x6c, 0x69, 0x65, 0x6e, 0x74, 0x5f, 0x73,
	0x65, 0x63, 0x72, 0x65, 0x74, 0x18, 0x02, 0x20, 0x01, 0x28, 0x09, 0x48, 0x01, 0x52, 0x0c, 0x63,
	0x6c, 0x69, 0x65, 0x6e, 0x74, 0x53, 0x65, 0x63, 0x72, 0x65, 0x74, 0x88, 0x01, 0x01, 0x12, 0x37,
	0x0a, 0x15, 0x63, 0x6c, 0x69, 0x65, 0x6e, 0x74, 0x5f, 0x61, 0x73, 0x73, 0x65, 0x72, 0x74, 0x69,
	0x6f, 0x6e, 0x5f, 0x74, 0x79, 0x70, 0x65, 0x18, 0x03, 0x20, 0x01, 0x28, 0x09, 0x48, 0x02, 0x52,
	0x13, 0x63, 0x6c, 0x69, 0x65, 0x6e, 0x74, 0x41, 0x73, 0x73, 0x65, 0x72, 0x74, 0x69, 0x6f, 0x6e,
	0x54, 0x79, 0x70, 0x65, 0x88, 0x01, 0x01, 0x12, 0x2e, 0x0a, 0x10, 0x63, 0x6c, 0x69, 0x65, 0x6e,
	0x74, 0x5f, 0x61, 0x73, 0x73, 0x65, 0x72, 0x74, 0x69, 0x6f, 0x6e, 0x18, 0x04, 0x20, 0x01, 0x28,
	0x09, 0x48, 0x03, 0x52, 0x0f, 0x63, 0x6c, 0x69, 0x65, 0x6e, 0x74, 0x41, 0x73, 0x73, 0x65, 0x72,
	0x74, 0x69, 0x6f, 0x6e, 0x88, 0x01, 0x01, 0x42, 0x0c, 0x0a, 0x0a, 0x5f, 0x63, 0x6c, 0x69, 0x65,
	0x6e, 0x74, 0x5f, 0x69, 0x64, 0x42, 0x10, 0x0a, 0x0e, 0x5f, 0x63, 0x6c, 0x69, 0x65, 0x6e, 0x74,
	0x5f, 0x73, 0x65, 0x63, 0x72, 0x65, 0x74, 0x42, 0x18, 0x0a, 0x16, 0x5f, 0x63, 0x6c, 0x69, 0x65,
	0x6e, 0x74, 0x5f, 0x61, 0x73, 0x73, 0x65, 0x72, 0x74, 0x69, 0x6f, 0x6e, 0x5f, 0x74, 0x79, 0x70,
	0x65, 0x42, 0x13, 0x0a, 0x11, 0x5f, 0x63, 0x6c, 0x69, 0x65, 0x6e, 0x74, 0x5f, 0x61, 0x73, 0x73,
	0x65, 0x72, 0x74, 0x69, 0x6f, 0x6e, 0x22, 0x77, 0x0a, 0x1c, 0x43, 0x6c, 0x69, 0x65, 0x6e, 0x74,
	0x41, 0x75, 0x74, 0x68, 0x65, 0x6e, 0x74, 0x69, 0x63, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x52, 0x65,
	0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x12, 0x29, 0x0a, 0x05, 0x65, 0x72, 0x72, 0x6f, 0x72, 0x18,
	0x01, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x13, 0x2e, 0x6f, 0x69, 0x64, 0x63, 0x2e, 0x63, 0x6f, 0x72,
	0x65, 0x2e, 0x76, 0x31, 0x2e, 0x45, 0x72, 0x72, 0x6f, 0x72, 0x52, 0x05, 0x65, 0x72, 0x72, 0x6f,
	0x72, 0x12, 0x2c, 0x0a, 0x06, 0x63, 0x6c, 0x69, 0x65, 0x6e, 0x74, 0x18, 0x02, 0x20, 0x01, 0x28,
	0x0b, 0x32, 0x14, 0x2e, 0x6f, 0x69, 0x64, 0x63, 0x2e, 0x63, 0x6f, 0x72, 0x65, 0x2e, 0x76, 0x31,
	0x2e, 0x43, 0x6c, 0x69, 0x65, 0x6e, 0x74, 0x52, 0x06, 0x63, 0x6c, 0x69, 0x65, 0x6e, 0x74, 0x22,
	0x51, 0x0a, 0x19, 0x43, 0x6c, 0x69, 0x65, 0x6e, 0x74, 0x52, 0x65, 0x67, 0x69, 0x73, 0x74, 0x72,
	0x61, 0x74, 0x69, 0x6f, 0x6e, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x12, 0x34, 0x0a, 0x08,
	0x6d, 0x65, 0x74, 0x61, 0x64, 0x61, 0x74, 0x61, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x18,
	0x2e, 0x6f, 0x69, 0x64, 0x63, 0x2e, 0x63, 0x6f, 0x72, 0x65, 0x2e, 0x76, 0x31, 0x2e, 0x43, 0x6c,
	0x69, 0x65, 0x6e, 0x74, 0x4d, 0x65, 0x74, 0x61, 0x52, 0x08, 0x6d, 0x65, 0x74, 0x61, 0x64, 0x61,
	0x74, 0x61, 0x22, 0x75, 0x0a, 0x1a, 0x43, 0x6c, 0x69, 0x65, 0x6e, 0x74, 0x52, 0x65, 0x67, 0x69,
	0x73, 0x74, 0x72, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65,
	0x12, 0x29, 0x0a, 0x05, 0x65, 0x72, 0x72, 0x6f, 0x72, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0b, 0x32,
	0x13, 0x2e, 0x6f, 0x69, 0x64, 0x63, 0x2e, 0x63, 0x6f, 0x72, 0x65, 0x2e, 0x76, 0x31, 0x2e, 0x45,
	0x72, 0x72, 0x6f, 0x72, 0x52, 0x05, 0x65, 0x72, 0x72, 0x6f, 0x72, 0x12, 0x2c, 0x0a, 0x06, 0x63,
	0x6c, 0x69, 0x65, 0x6e, 0x74, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x14, 0x2e, 0x6f, 0x69,
	0x64, 0x63, 0x2e, 0x63, 0x6f, 0x72, 0x65, 0x2e, 0x76, 0x31, 0x2e, 0x43, 0x6c, 0x69, 0x65, 0x6e,
	0x74, 0x52, 0x06, 0x63, 0x6c, 0x69, 0x65, 0x6e, 0x74, 0x32, 0x82, 0x01, 0x0a, 0x17, 0x43, 0x6c,
	0x69, 0x65, 0x6e, 0x74, 0x41, 0x75, 0x74, 0x68, 0x65, 0x6e, 0x74, 0x69, 0x63, 0x61, 0x74, 0x69,
	0x6f, 0x6e, 0x41, 0x50, 0x49, 0x12, 0x67, 0x0a, 0x0c, 0x41, 0x75, 0x74, 0x68, 0x65, 0x6e, 0x74,
	0x69, 0x63, 0x61, 0x74, 0x65, 0x12, 0x29, 0x2e, 0x6f, 0x69, 0x64, 0x63, 0x2e, 0x63, 0x6f, 0x72,
	0x65, 0x2e, 0x76, 0x31, 0x2e, 0x43, 0x6c, 0x69, 0x65, 0x6e, 0x74, 0x41, 0x75, 0x74, 0x68, 0x65,
	0x6e, 0x74, 0x69, 0x63, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74,
	0x1a, 0x2a, 0x2e, 0x6f, 0x69, 0x64, 0x63, 0x2e, 0x63, 0x6f, 0x72, 0x65, 0x2e, 0x76, 0x31, 0x2e,
	0x43, 0x6c, 0x69, 0x65, 0x6e, 0x74, 0x41, 0x75, 0x74, 0x68, 0x65, 0x6e, 0x74, 0x69, 0x63, 0x61,
	0x74, 0x69, 0x6f, 0x6e, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x22, 0x00, 0x32, 0x78,
	0x0a, 0x15, 0x43, 0x6c, 0x69, 0x65, 0x6e, 0x74, 0x52, 0x65, 0x67, 0x69, 0x73, 0x74, 0x72, 0x61,
	0x74, 0x69, 0x6f, 0x6e, 0x41, 0x50, 0x49, 0x12, 0x5f, 0x0a, 0x08, 0x52, 0x65, 0x67, 0x69, 0x73,
	0x74, 0x65, 0x72, 0x12, 0x27, 0x2e, 0x6f, 0x69, 0x64, 0x63, 0x2e, 0x63, 0x6f, 0x72, 0x65, 0x2e,
	0x76, 0x31, 0x2e, 0x43, 0x6c, 0x69, 0x65, 0x6e, 0x74, 0x52, 0x65, 0x67, 0x69, 0x73, 0x74, 0x72,
	0x61, 0x74, 0x69, 0x6f, 0x6e, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x1a, 0x28, 0x2e, 0x6f,
	0x69, 0x64, 0x63, 0x2e, 0x63, 0x6f, 0x72, 0x65, 0x2e, 0x76, 0x31, 0x2e, 0x43, 0x6c, 0x69, 0x65,
	0x6e, 0x74, 0x52, 0x65, 0x67, 0x69, 0x73, 0x74, 0x72, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x52, 0x65,
	0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x22, 0x00, 0x42, 0x15, 0x5a, 0x13, 0x6f, 0x69, 0x64, 0x63,
	0x2f, 0x63, 0x6f, 0x72, 0x65, 0x2f, 0x76, 0x31, 0x3b, 0x63, 0x6f, 0x72, 0x65, 0x76, 0x31, 0x62,
	0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_oidc_core_v1_client_api_proto_rawDescOnce sync.Once
	file_oidc_core_v1_client_api_proto_rawDescData = file_oidc_core_v1_client_api_proto_rawDesc
)

func file_oidc_core_v1_client_api_proto_rawDescGZIP() []byte {
	file_oidc_core_v1_client_api_proto_rawDescOnce.Do(func() {
		file_oidc_core_v1_client_api_proto_rawDescData = protoimpl.X.CompressGZIP(file_oidc_core_v1_client_api_proto_rawDescData)
	})
	return file_oidc_core_v1_client_api_proto_rawDescData
}

var file_oidc_core_v1_client_api_proto_msgTypes = make([]protoimpl.MessageInfo, 4)
var file_oidc_core_v1_client_api_proto_goTypes = []interface{}{
	(*ClientAuthenticationRequest)(nil),  // 0: oidc.core.v1.ClientAuthenticationRequest
	(*ClientAuthenticationResponse)(nil), // 1: oidc.core.v1.ClientAuthenticationResponse
	(*ClientRegistrationRequest)(nil),    // 2: oidc.core.v1.ClientRegistrationRequest
	(*ClientRegistrationResponse)(nil),   // 3: oidc.core.v1.ClientRegistrationResponse
	(*Error)(nil),                        // 4: oidc.core.v1.Error
	(*Client)(nil),                       // 5: oidc.core.v1.Client
	(*ClientMeta)(nil),                   // 6: oidc.core.v1.ClientMeta
}
var file_oidc_core_v1_client_api_proto_depIdxs = []int32{
	4, // 0: oidc.core.v1.ClientAuthenticationResponse.error:type_name -> oidc.core.v1.Error
	5, // 1: oidc.core.v1.ClientAuthenticationResponse.client:type_name -> oidc.core.v1.Client
	6, // 2: oidc.core.v1.ClientRegistrationRequest.metadata:type_name -> oidc.core.v1.ClientMeta
	4, // 3: oidc.core.v1.ClientRegistrationResponse.error:type_name -> oidc.core.v1.Error
	5, // 4: oidc.core.v1.ClientRegistrationResponse.client:type_name -> oidc.core.v1.Client
	0, // 5: oidc.core.v1.ClientAuthenticationAPI.Authenticate:input_type -> oidc.core.v1.ClientAuthenticationRequest
	2, // 6: oidc.core.v1.ClientRegistrationAPI.Register:input_type -> oidc.core.v1.ClientRegistrationRequest
	1, // 7: oidc.core.v1.ClientAuthenticationAPI.Authenticate:output_type -> oidc.core.v1.ClientAuthenticationResponse
	3, // 8: oidc.core.v1.ClientRegistrationAPI.Register:output_type -> oidc.core.v1.ClientRegistrationResponse
	7, // [7:9] is the sub-list for method output_type
	5, // [5:7] is the sub-list for method input_type
	5, // [5:5] is the sub-list for extension type_name
	5, // [5:5] is the sub-list for extension extendee
	0, // [0:5] is the sub-list for field type_name
}

func init() { file_oidc_core_v1_client_api_proto_init() }
func file_oidc_core_v1_client_api_proto_init() {
	if File_oidc_core_v1_client_api_proto != nil {
		return
	}
	file_oidc_core_v1_client_proto_init()
	file_oidc_core_v1_error_proto_init()
	if !protoimpl.UnsafeEnabled {
		file_oidc_core_v1_client_api_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*ClientAuthenticationRequest); i {
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
		file_oidc_core_v1_client_api_proto_msgTypes[1].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*ClientAuthenticationResponse); i {
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
		file_oidc_core_v1_client_api_proto_msgTypes[2].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*ClientRegistrationRequest); i {
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
		file_oidc_core_v1_client_api_proto_msgTypes[3].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*ClientRegistrationResponse); i {
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
	file_oidc_core_v1_client_api_proto_msgTypes[0].OneofWrappers = []interface{}{}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_oidc_core_v1_client_api_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   4,
			NumExtensions: 0,
			NumServices:   2,
		},
		GoTypes:           file_oidc_core_v1_client_api_proto_goTypes,
		DependencyIndexes: file_oidc_core_v1_client_api_proto_depIdxs,
		MessageInfos:      file_oidc_core_v1_client_api_proto_msgTypes,
	}.Build()
	File_oidc_core_v1_client_api_proto = out.File
	file_oidc_core_v1_client_api_proto_rawDesc = nil
	file_oidc_core_v1_client_api_proto_goTypes = nil
	file_oidc_core_v1_client_api_proto_depIdxs = nil
}