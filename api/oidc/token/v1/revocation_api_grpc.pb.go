// Code generated by protoc-gen-go-grpc. DO NOT EDIT.
// versions:
// - protoc-gen-go-grpc v1.2.0
// - protoc             (unknown)
// source: oidc/token/v1/revocation_api.proto

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

// RevocatonServiceClient is the client API for RevocatonService service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://pkg.go.dev/google.golang.org/grpc/?tab=doc#ClientConn.NewStream.
type RevocatonServiceClient interface {
	Revoke(ctx context.Context, in *RevokeRequest, opts ...grpc.CallOption) (*RevokeResponse, error)
}

type revocatonServiceClient struct {
	cc grpc.ClientConnInterface
}

func NewRevocatonServiceClient(cc grpc.ClientConnInterface) RevocatonServiceClient {
	return &revocatonServiceClient{cc}
}

func (c *revocatonServiceClient) Revoke(ctx context.Context, in *RevokeRequest, opts ...grpc.CallOption) (*RevokeResponse, error) {
	out := new(RevokeResponse)
	err := c.cc.Invoke(ctx, "/oidc.token.v1.RevocatonService/Revoke", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// RevocatonServiceServer is the server API for RevocatonService service.
// All implementations must embed UnimplementedRevocatonServiceServer
// for forward compatibility
type RevocatonServiceServer interface {
	Revoke(context.Context, *RevokeRequest) (*RevokeResponse, error)
	mustEmbedUnimplementedRevocatonServiceServer()
}

// UnimplementedRevocatonServiceServer must be embedded to have forward compatible implementations.
type UnimplementedRevocatonServiceServer struct {
}

func (UnimplementedRevocatonServiceServer) Revoke(context.Context, *RevokeRequest) (*RevokeResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method Revoke not implemented")
}
func (UnimplementedRevocatonServiceServer) mustEmbedUnimplementedRevocatonServiceServer() {}

// UnsafeRevocatonServiceServer may be embedded to opt out of forward compatibility for this service.
// Use of this interface is not recommended, as added methods to RevocatonServiceServer will
// result in compilation errors.
type UnsafeRevocatonServiceServer interface {
	mustEmbedUnimplementedRevocatonServiceServer()
}

func RegisterRevocatonServiceServer(s grpc.ServiceRegistrar, srv RevocatonServiceServer) {
	s.RegisterService(&RevocatonService_ServiceDesc, srv)
}

func _RevocatonService_Revoke_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(RevokeRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(RevocatonServiceServer).Revoke(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/oidc.token.v1.RevocatonService/Revoke",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(RevocatonServiceServer).Revoke(ctx, req.(*RevokeRequest))
	}
	return interceptor(ctx, in, info, handler)
}

// RevocatonService_ServiceDesc is the grpc.ServiceDesc for RevocatonService service.
// It's only intended for direct use with grpc.RegisterService,
// and not to be introspected or modified (even as a copy)
var RevocatonService_ServiceDesc = grpc.ServiceDesc{
	ServiceName: "oidc.token.v1.RevocatonService",
	HandlerType: (*RevocatonServiceServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "Revoke",
			Handler:    _RevocatonService_Revoke_Handler,
		},
	},
	Streams:  []grpc.StreamDesc{},
	Metadata: "oidc/token/v1/revocation_api.proto",
}