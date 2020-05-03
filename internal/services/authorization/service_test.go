package authorization

import (
	"context"
	"fmt"
	"testing"

	corev1 "go.zenithar.org/solid/api/gen/go/oidc/core/v1"
	registrationv1 "go.zenithar.org/solid/api/gen/go/oidc/registration/v1"
	authzmock "go.zenithar.org/solid/pkg/authorization/mock"
	"go.zenithar.org/solid/pkg/rfcerrors"
	"go.zenithar.org/solid/pkg/storage"
	storagemock "go.zenithar.org/solid/pkg/storage/mock"

	"github.com/golang/mock/gomock"
	"github.com/golang/protobuf/ptypes/wrappers"
	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
)

var (
	cmpOpts = []cmp.Option{
		cmpopts.IgnoreUnexported(wrappers.StringValue{}),
		cmpopts.IgnoreUnexported(corev1.AuthenticationRequest{}),
		cmpopts.IgnoreUnexported(corev1.AuthenticationResponse{}),
		cmpopts.IgnoreUnexported(corev1.Error{}),
	}
)

func Test_Authorize(t *testing.T) {
	type args struct {
		ctx context.Context
		req *corev1.AuthenticationRequest
	}
	tests := []struct {
		name    string
		args    args
		prepare func(*authzmock.MockCodeGenerator, *storagemock.MockClientReader)
		want    *corev1.AuthenticationResponse
		wantErr bool
	}{
		{
			name: "nil",
			args: args{
				ctx: context.Background(),
				req: nil,
			},
			wantErr: true,
			want: &corev1.AuthenticationResponse{
				Error: &corev1.Error{
					Err: "invalid_request",
					ErrorDescription: &wrappers.StringValue{
						Value: "request is nil",
					},
				},
			},
		},
		{
			name: "empty request",
			args: args{
				ctx: context.Background(),
				req: &corev1.AuthenticationRequest{},
			},
			wantErr: true,
			want: &corev1.AuthenticationResponse{
				Error: rfcerrors.InvalidRequest("<missing>"),
			},
		},
		{
			name: "missing scope",
			args: args{
				ctx: context.Background(),
				req: &corev1.AuthenticationRequest{
					ResponseType: "code",
					ClientId:     "s6BhdRkqt3",
					State:        "af0ifjsldkj",
					RedirectUri:  "https://client.example.org/cb",
				},
			},
			wantErr: true,
			want: &corev1.AuthenticationResponse{
				Error: rfcerrors.InvalidRequest("af0ifjsldkj"),
			},
		},
		{
			name: "missing response_type",
			args: args{
				ctx: context.Background(),
				req: &corev1.AuthenticationRequest{
					Scope:       "openid profile email",
					ClientId:    "s6BhdRkqt3",
					State:       "af0ifjsldkj",
					RedirectUri: "https://client.example.org/cb",
				},
			},
			wantErr: true,
			want: &corev1.AuthenticationResponse{
				Error: rfcerrors.InvalidRequest("af0ifjsldkj"),
			},
		},
		{
			name: "missing client_id",
			args: args{
				ctx: context.Background(),
				req: &corev1.AuthenticationRequest{
					ResponseType: "code",
					Scope:        "openid profile email",
					State:        "af0ifjsldkj",
					RedirectUri:  "https://client.example.org/cb",
				},
			},
			wantErr: true,
			want: &corev1.AuthenticationResponse{
				Error: rfcerrors.InvalidRequest("af0ifjsldkj"),
			},
		},
		{
			name: "missing redirect_uri",
			args: args{
				ctx: context.Background(),
				req: &corev1.AuthenticationRequest{
					ResponseType: "code",
					Scope:        "openid profile email",
					ClientId:     "s6BhdRkqt3",
					State:        "af0ifjsldkj",
				},
			},
			wantErr: true,
			want: &corev1.AuthenticationResponse{
				Error: rfcerrors.InvalidRequest("af0ifjsldkj"),
			},
		},
		{
			name: "missing state",
			args: args{
				ctx: context.Background(),
				req: &corev1.AuthenticationRequest{
					ResponseType: "code",
					Scope:        "openid profile email",
					ClientId:     "s6BhdRkqt3",
					RedirectUri:  "https://client.example.org/cb",
				},
			},
			wantErr: true,
			want: &corev1.AuthenticationResponse{
				Error: rfcerrors.InvalidRequest("<missing>"),
			},
		},
		{
			name: "error client not found",
			args: args{
				ctx: context.Background(),
				req: &corev1.AuthenticationRequest{
					ResponseType: "code",
					Scope:        "openid profile email",
					ClientId:     "s6BhdRkqt3",
					State:        "af0ifjsldkj",
					RedirectUri:  "https://client.example.org/cb",
				},
			},
			prepare: func(cg *authzmock.MockCodeGenerator, clients *storagemock.MockClientReader) {
				clients.EXPECT().Get(gomock.Any(), "s6BhdRkqt3").Return(nil, storage.ErrNotFound)
			},
			wantErr: true,
			want: &corev1.AuthenticationResponse{
				Error: rfcerrors.InvalidRequest("af0ifjsldkj"),
			},
		},
		{
			name: "error during code generation",
			args: args{
				ctx: context.Background(),
				req: &corev1.AuthenticationRequest{
					ResponseType: "code",
					Scope:        "openid profile email",
					ClientId:     "s6BhdRkqt3",
					State:        "af0ifjsldkj",
					RedirectUri:  "https://client.example.org/cb",
				},
			},
			prepare: func(cg *authzmock.MockCodeGenerator, clients *storagemock.MockClientReader) {
				clients.EXPECT().Get(gomock.Any(), "s6BhdRkqt3").Return(&registrationv1.Client{}, nil)
				cg.EXPECT().Generate(gomock.Any()).Return("", fmt.Errorf("foo"))
			},
			wantErr: true,
			want: &corev1.AuthenticationResponse{
				Error: rfcerrors.ServerError("af0ifjsldkj"),
			},
		},
		// ---------------------------------------------------------------------
		{
			name: "valid",
			args: args{
				ctx: context.Background(),
				req: &corev1.AuthenticationRequest{
					ResponseType: "code",
					Scope:        "openid profile email",
					ClientId:     "s6BhdRkqt3",
					State:        "af0ifjsldkj",
					RedirectUri:  "https://client.example.org/cb",
				},
			},
			prepare: func(cg *authzmock.MockCodeGenerator, clients *storagemock.MockClientReader) {
				clients.EXPECT().Get(gomock.Any(), "s6BhdRkqt3").Return(&registrationv1.Client{}, nil)
				cg.EXPECT().Generate(gomock.Any()).Return("1234567891234567890", nil)
			},
			wantErr: false,
			want: &corev1.AuthenticationResponse{
				Error: nil,
				Code:  "1234567891234567890",
				State: "af0ifjsldkj",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			// Arm mocks
			cg := authzmock.NewMockCodeGenerator(ctrl)
			clients := storagemock.NewMockClientReader(ctrl)

			// Prepare them
			if tt.prepare != nil {
				tt.prepare(cg, clients)
			}

			s := New(cg, clients)
			got, err := s.Authorize(tt.args.ctx, tt.args.req)
			if (err != nil) != tt.wantErr {
				t.Errorf("service.Authorize() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if diff := cmp.Diff(got, tt.want, cmpOpts...); diff != "" {
				t.Errorf("service.Authorize() res =%s", diff)
			}
		})
	}
}
