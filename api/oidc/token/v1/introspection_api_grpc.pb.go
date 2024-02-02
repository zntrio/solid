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

// Code generated by protoc-gen-go-grpc. DO NOT EDIT.
// versions:
// - protoc-gen-go-grpc v1.3.0
// - protoc             (unknown)
// source: oidc/token/v1/introspection_api.proto

package tokenv1

import (
	context "context"
	grpc "google.golang.org/grpc"
	codes "google.golang.org/grpc/codes"
	status "google.golang.org/grpc/status"
)

// This is a compile-time assertion to ensure that this generated file
// is compatible with the grpc package it is being compiled against.
// Requires gRPC-Go v1.32.0 or later.
const _ = grpc.SupportPackageIsVersion7

const (
	IntrospectionService_Introspect_FullMethodName = "/oidc.token.v1.IntrospectionService/Introspect"
)

// IntrospectionServiceClient is the client API for IntrospectionService service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://pkg.go.dev/google.golang.org/grpc/?tab=doc#ClientConn.NewStream.
type IntrospectionServiceClient interface {
	Introspect(ctx context.Context, in *IntrospectRequest, opts ...grpc.CallOption) (*IntrospectResponse, error)
}

type introspectionServiceClient struct {
	cc grpc.ClientConnInterface
}

func NewIntrospectionServiceClient(cc grpc.ClientConnInterface) IntrospectionServiceClient {
	return &introspectionServiceClient{cc}
}

func (c *introspectionServiceClient) Introspect(ctx context.Context, in *IntrospectRequest, opts ...grpc.CallOption) (*IntrospectResponse, error) {
	out := new(IntrospectResponse)
	err := c.cc.Invoke(ctx, IntrospectionService_Introspect_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// IntrospectionServiceServer is the server API for IntrospectionService service.
// All implementations should embed UnimplementedIntrospectionServiceServer
// for forward compatibility
type IntrospectionServiceServer interface {
	Introspect(context.Context, *IntrospectRequest) (*IntrospectResponse, error)
}

// UnimplementedIntrospectionServiceServer should be embedded to have forward compatible implementations.
type UnimplementedIntrospectionServiceServer struct {
}

func (UnimplementedIntrospectionServiceServer) Introspect(context.Context, *IntrospectRequest) (*IntrospectResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method Introspect not implemented")
}

// UnsafeIntrospectionServiceServer may be embedded to opt out of forward compatibility for this service.
// Use of this interface is not recommended, as added methods to IntrospectionServiceServer will
// result in compilation errors.
type UnsafeIntrospectionServiceServer interface {
	mustEmbedUnimplementedIntrospectionServiceServer()
}

func RegisterIntrospectionServiceServer(s grpc.ServiceRegistrar, srv IntrospectionServiceServer) {
	s.RegisterService(&IntrospectionService_ServiceDesc, srv)
}

func _IntrospectionService_Introspect_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(IntrospectRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(IntrospectionServiceServer).Introspect(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: IntrospectionService_Introspect_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(IntrospectionServiceServer).Introspect(ctx, req.(*IntrospectRequest))
	}
	return interceptor(ctx, in, info, handler)
}

// IntrospectionService_ServiceDesc is the grpc.ServiceDesc for IntrospectionService service.
// It's only intended for direct use with grpc.RegisterService,
// and not to be introspected or modified (even as a copy)
var IntrospectionService_ServiceDesc = grpc.ServiceDesc{
	ServiceName: "oidc.token.v1.IntrospectionService",
	HandlerType: (*IntrospectionServiceServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "Introspect",
			Handler:    _IntrospectionService_Introspect_Handler,
		},
	},
	Streams:  []grpc.StreamDesc{},
	Metadata: "oidc/token/v1/introspection_api.proto",
}
