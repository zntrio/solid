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
// source: oidc/flow/v1/flow.proto

package flowv1

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

// An Authentication Request is an OAuth 2.0 Authorization Request that requests
// that the End-User be authenticated by the Authorization Server.
type AuthorizationRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// REQUIRED. OpenID Connect requests MUST contain the openid scope value. If
	// the openid scope value is not present, the behavior is entirely unspecified.
	// Other scope values MAY be present. Scope values used that are not understood
	// by an implementation SHOULD be ignored.
	Scope string `protobuf:"bytes,1,opt,name=scope,proto3" json:"scope,omitempty"`
	// REQUIRED. OAuth 2.0 Response Type value that determines the authorization
	// processing flow to be used, including what parameters are returned from
	// the endpoints used. When using the Authorization Code Flow, this value is
	// code.
	ResponseType string `protobuf:"bytes,2,opt,name=response_type,json=responseType,proto3" json:"response_type,omitempty"`
	// REQUIRED. OAuth 2.0 Client Identifier valid at the Authorization Server.
	ClientId string `protobuf:"bytes,3,opt,name=client_id,json=clientId,proto3" json:"client_id,omitempty"`
	// REQUIRED. Redirection URI to which the response will be sent. This URI
	// MUST exactly match one of the Redirection URI values for the Client
	// pre-registered at the OpenID Provider, with the matching performed as
	// described in Section 6.2.1 of [RFC3986] (Simple String Comparison).
	// When using this flow, the Redirection URI SHOULD use the https scheme;
	// however, it MAY use the http scheme, provided that the Client Type is
	// confidential, as defined in Section 2.1 of OAuth 2.0, and provided the OP
	// allows the use of http Redirection URIs in this case. The Redirection URI
	// MAY use an alternate scheme, such as one that is intended to identify a
	// callback into a native application.
	RedirectUri string `protobuf:"bytes,4,opt,name=redirect_uri,json=redirectUri,proto3" json:"redirect_uri,omitempty"`
	// RECOMMENDED. Opaque value used to maintain state between the request and
	// the callback. Typically, Cross-Site Request Forgery (CSRF, XSRF) mitigation
	// is done by cryptographically binding the value of this parameter with a
	// browser cookie.
	State string `protobuf:"bytes,5,opt,name=state,proto3" json:"state,omitempty"`
	// OPTIONAL. Informs the Authorization Server of the mechanism to be used for
	// returning parameters from the Authorization Endpoint. This use of this
	// parameter is NOT RECOMMENDED when the Response Mode that would be requested
	// is the default mode specified for the Response Type.
	ResponseMode *string `protobuf:"bytes,6,opt,name=response_mode,json=responseMode,proto3,oneof" json:"response_mode,omitempty"`
	// OPTIONAL. String value used to associate a Client session with an ID Token,
	// and to mitigate replay attacks. The value is passed through unmodified from
	// the Authentication Request to the ID Token. Sufficient entropy MUST be
	// present in the nonce values used to prevent attackers from guessing values.
	// https://tools.ietf.org/html/draft-ietf-oauth-security-topics-15#section-4.5.3
	Nonce string `protobuf:"bytes,7,opt,name=nonce,proto3" json:"nonce,omitempty"`
	// OPTIONAL. ASCII string value that specifies how the Authorization Server
	// displays the authentication and consent user interface pages to the End-User.
	Display *string `protobuf:"bytes,8,opt,name=display,proto3,oneof" json:"display,omitempty"`
	// OPTIONAL. Space delimited, case sensitive list of ASCII string values that
	// specifies whether the Authorization Server prompts the End-User for
	// reauthentication and consent.
	Prompt *string `protobuf:"bytes,9,opt,name=prompt,proto3,oneof" json:"prompt,omitempty"`
	// OPTIONAL. Maximum Authentication Age. Specifies the allowable elapsed time
	// in seconds since the last time the End-User was actively authenticated by
	// the OP. If the elapsed time is greater than this value, the OP MUST attempt
	// to actively re-authenticate the End-User. (The max_age request parameter
	// corresponds to the OpenID 2.0 PAPE [OpenID.PAPE] max_auth_age request
	// parameter.) When max_age is used, the ID Token returned MUST include an
	// auth_time Claim Value.
	MaxAge *uint64 `protobuf:"varint,10,opt,name=max_age,json=maxAge,proto3,oneof" json:"max_age,omitempty"`
	// OPTIONAL. End-User's preferred languages and scripts for the user
	// interface, represented as a space-separated list of BCP47 [RFC5646]
	// language tag values, ordered by preference. For instance, the value "fr-CA
	// fr en" represents a preference for French as spoken in Canada, then French
	// (without a region designation), followed by English (without a region
	// designation). An error SHOULD NOT result if some or all of the requested
	// locales are not supported by the OpenID Provider.
	UiLocales *string `protobuf:"bytes,11,opt,name=ui_locales,json=uiLocales,proto3,oneof" json:"ui_locales,omitempty"`
	// OPTIONAL. ID Token previously issued by the Authorization Server being
	// passed as a hint about the End-User's current or past authenticated session
	// with the Client. If the End-User identified by the ID Token is logged in or
	// is logged in by the request, then the Authorization Server returns a
	// positive response; otherwise, it SHOULD return an error, such as
	// login_required. When possible, an id_token_hint SHOULD be present when
	// prompt=none is used and an invalid_request error MAY be returned if it is
	// not; however, the server SHOULD respond successfully when possible, even
	// if it is not present. The Authorization Server need not be listed as an
	// audience of the ID Token when it is used as an id_token_hint value.
	// If the ID Token received by the RP from the OP is encrypted, to use it as
	// an id_token_hint, the Client MUST decrypt the signed ID Token contained
	// within the encrypted ID Token. The Client MAY re-encrypt the signed ID
	// token to the Authentication Server using a key that enables the server to
	// decrypt the ID Token, and use the re-encrypted ID token as the
	// id_token_hint value.
	IdTokenHint *string `protobuf:"bytes,12,opt,name=id_token_hint,json=idTokenHint,proto3,oneof" json:"id_token_hint,omitempty"`
	// OPTIONAL. Requested Authentication Context Class Reference values.
	// Space-separated string that specifies the acr values that the Authorization
	// Server is being requested to use for processing this Authentication
	// Request, with the values appearing in order of preference. The
	// Authentication Context Class satisfied by the authentication performed is
	// returned as the acr Claim Value, as specified in Section 2. The acr Claim
	// is requested as a Voluntary Claim by this parameter.
	AcrValues *string `protobuf:"bytes,13,opt,name=acr_values,json=acrValues,proto3,oneof" json:"acr_values,omitempty"`
	// OPTIONAL. This parameter enables OpenID Connect requests to be passed in a
	// single, self-contained parameter and to be optionally signed and/or
	// encrypted. The parameter value is a Request Object value, as specified in
	// Section 6.1. It represents the request as a JWT whose Claims are the
	// request parameters.
	Request *string `protobuf:"bytes,14,opt,name=request,proto3,oneof" json:"request,omitempty"`
	// OPTIONAL. This parameter enables OpenID Connect requests to be passed by
	// reference, rather than by value. The request_uri value is a URL using the
	// https scheme referencing a resource containing a Request Object value,
	// which is a JWT containing the request parameters.
	RequestUri *string `protobuf:"bytes,15,opt,name=request_uri,json=requestUri,proto3,oneof" json:"request_uri,omitempty"`
	// REQUIRED. This parameter enables PKCE flow.
	CodeChallenge string `protobuf:"bytes,16,opt,name=code_challenge,json=codeChallenge,proto3" json:"code_challenge,omitempty"`
	// REQUIRED. This parameter enables PKCE flow.
	CodeChallengeMethod string `protobuf:"bytes,17,opt,name=code_challenge_method,json=codeChallengeMethod,proto3" json:"code_challenge_method,omitempty"`
	// REQUIRED. Add targeted audience.
	Audience string `protobuf:"bytes,18,opt,name=audience,proto3" json:"audience,omitempty"`
	// OPTIONAL.
	// https://tools.ietf.org/html/draft-fett-oauth-dpop-04#section-5
	DpopProof *string `protobuf:"bytes,19,opt,name=dpop_proof,json=dpopProof,proto3,oneof" json:"dpop_proof,omitempty"`
	// OPTIONAL
	// https://tools.ietf.org/html/rfc8707
	// Indicates the target service or resource to which access is being
	// requested.  Its value MUST be an absolute URI, as specified by
	// Section 4.3 of [RFC3986].  The URI MUST NOT include a fragment
	// component.  It SHOULD NOT include a query component, but it is
	// recognized that there are cases that make a query component a
	// useful and necessary part of the resource parameter, such as when
	// one or more query parameters are used to scope requests to an
	// application.  The "resource" parameter URI value is an identifier
	// representing the identity of the resource, which MAY be a locator
	// that corresponds to a network-addressable location where the
	// target resource is hosted.  Multiple "resource" parameters MAY be
	// used to indicate that the requested token is intended to be used
	// at multiple resources.
	Resource []string `protobuf:"bytes,20,rep,name=resource,proto3" json:"resource,omitempty"`
	// OPTIONAL.
	// Issuer url used for JARM decoding.
	Iss *string `protobuf:"bytes,21,opt,name=iss,proto3,oneof" json:"iss,omitempty"`
	// OPTIONAL. A token containing information identifying the end-user for whom
	// authentication is being requested. The particular details and security
	// requirements for the login_hint_token as well as how the end-user is
	// identified by its content are deployment or profile specific.
	LoginHintToken *string `protobuf:"bytes,22,opt,name=login_hint_token,json=loginHintToken,proto3,oneof" json:"login_hint_token,omitempty"`
	// OPTIONAL. A hint to the OpenID Provider regarding the end-user for whom
	// authentication is being requested. The value may contain an email address,
	// phone number, account number, subject identifier, username, etc., which
	// identifies the end-user to the OP. The value may be directly collected from
	// the user by the Client before requesting authentication at the OP, for
	// example, but may also be obtained by other means.
	LoginHint *string `protobuf:"bytes,23,opt,name=login_hint,json=loginHint,proto3,oneof" json:"login_hint,omitempty"`
}

func (x *AuthorizationRequest) Reset() {
	*x = AuthorizationRequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_oidc_flow_v1_flow_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *AuthorizationRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*AuthorizationRequest) ProtoMessage() {}

func (x *AuthorizationRequest) ProtoReflect() protoreflect.Message {
	mi := &file_oidc_flow_v1_flow_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use AuthorizationRequest.ProtoReflect.Descriptor instead.
func (*AuthorizationRequest) Descriptor() ([]byte, []int) {
	return file_oidc_flow_v1_flow_proto_rawDescGZIP(), []int{0}
}

func (x *AuthorizationRequest) GetScope() string {
	if x != nil {
		return x.Scope
	}
	return ""
}

func (x *AuthorizationRequest) GetResponseType() string {
	if x != nil {
		return x.ResponseType
	}
	return ""
}

func (x *AuthorizationRequest) GetClientId() string {
	if x != nil {
		return x.ClientId
	}
	return ""
}

func (x *AuthorizationRequest) GetRedirectUri() string {
	if x != nil {
		return x.RedirectUri
	}
	return ""
}

func (x *AuthorizationRequest) GetState() string {
	if x != nil {
		return x.State
	}
	return ""
}

func (x *AuthorizationRequest) GetResponseMode() string {
	if x != nil && x.ResponseMode != nil {
		return *x.ResponseMode
	}
	return ""
}

func (x *AuthorizationRequest) GetNonce() string {
	if x != nil {
		return x.Nonce
	}
	return ""
}

func (x *AuthorizationRequest) GetDisplay() string {
	if x != nil && x.Display != nil {
		return *x.Display
	}
	return ""
}

func (x *AuthorizationRequest) GetPrompt() string {
	if x != nil && x.Prompt != nil {
		return *x.Prompt
	}
	return ""
}

func (x *AuthorizationRequest) GetMaxAge() uint64 {
	if x != nil && x.MaxAge != nil {
		return *x.MaxAge
	}
	return 0
}

func (x *AuthorizationRequest) GetUiLocales() string {
	if x != nil && x.UiLocales != nil {
		return *x.UiLocales
	}
	return ""
}

func (x *AuthorizationRequest) GetIdTokenHint() string {
	if x != nil && x.IdTokenHint != nil {
		return *x.IdTokenHint
	}
	return ""
}

func (x *AuthorizationRequest) GetAcrValues() string {
	if x != nil && x.AcrValues != nil {
		return *x.AcrValues
	}
	return ""
}

func (x *AuthorizationRequest) GetRequest() string {
	if x != nil && x.Request != nil {
		return *x.Request
	}
	return ""
}

func (x *AuthorizationRequest) GetRequestUri() string {
	if x != nil && x.RequestUri != nil {
		return *x.RequestUri
	}
	return ""
}

func (x *AuthorizationRequest) GetCodeChallenge() string {
	if x != nil {
		return x.CodeChallenge
	}
	return ""
}

func (x *AuthorizationRequest) GetCodeChallengeMethod() string {
	if x != nil {
		return x.CodeChallengeMethod
	}
	return ""
}

func (x *AuthorizationRequest) GetAudience() string {
	if x != nil {
		return x.Audience
	}
	return ""
}

func (x *AuthorizationRequest) GetDpopProof() string {
	if x != nil && x.DpopProof != nil {
		return *x.DpopProof
	}
	return ""
}

func (x *AuthorizationRequest) GetResource() []string {
	if x != nil {
		return x.Resource
	}
	return nil
}

func (x *AuthorizationRequest) GetIss() string {
	if x != nil && x.Iss != nil {
		return *x.Iss
	}
	return ""
}

func (x *AuthorizationRequest) GetLoginHintToken() string {
	if x != nil && x.LoginHintToken != nil {
		return *x.LoginHintToken
	}
	return ""
}

func (x *AuthorizationRequest) GetLoginHint() string {
	if x != nil && x.LoginHint != nil {
		return *x.LoginHint
	}
	return ""
}

var File_oidc_flow_v1_flow_proto protoreflect.FileDescriptor

var file_oidc_flow_v1_flow_proto_rawDesc = []byte{
	0x0a, 0x17, 0x6f, 0x69, 0x64, 0x63, 0x2f, 0x66, 0x6c, 0x6f, 0x77, 0x2f, 0x76, 0x31, 0x2f, 0x66,
	0x6c, 0x6f, 0x77, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12, 0x0c, 0x6f, 0x69, 0x64, 0x63, 0x2e,
	0x66, 0x6c, 0x6f, 0x77, 0x2e, 0x76, 0x31, 0x22, 0xd4, 0x07, 0x0a, 0x14, 0x41, 0x75, 0x74, 0x68,
	0x6f, 0x72, 0x69, 0x7a, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74,
	0x12, 0x14, 0x0a, 0x05, 0x73, 0x63, 0x6f, 0x70, 0x65, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52,
	0x05, 0x73, 0x63, 0x6f, 0x70, 0x65, 0x12, 0x23, 0x0a, 0x0d, 0x72, 0x65, 0x73, 0x70, 0x6f, 0x6e,
	0x73, 0x65, 0x5f, 0x74, 0x79, 0x70, 0x65, 0x18, 0x02, 0x20, 0x01, 0x28, 0x09, 0x52, 0x0c, 0x72,
	0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x54, 0x79, 0x70, 0x65, 0x12, 0x1b, 0x0a, 0x09, 0x63,
	0x6c, 0x69, 0x65, 0x6e, 0x74, 0x5f, 0x69, 0x64, 0x18, 0x03, 0x20, 0x01, 0x28, 0x09, 0x52, 0x08,
	0x63, 0x6c, 0x69, 0x65, 0x6e, 0x74, 0x49, 0x64, 0x12, 0x21, 0x0a, 0x0c, 0x72, 0x65, 0x64, 0x69,
	0x72, 0x65, 0x63, 0x74, 0x5f, 0x75, 0x72, 0x69, 0x18, 0x04, 0x20, 0x01, 0x28, 0x09, 0x52, 0x0b,
	0x72, 0x65, 0x64, 0x69, 0x72, 0x65, 0x63, 0x74, 0x55, 0x72, 0x69, 0x12, 0x14, 0x0a, 0x05, 0x73,
	0x74, 0x61, 0x74, 0x65, 0x18, 0x05, 0x20, 0x01, 0x28, 0x09, 0x52, 0x05, 0x73, 0x74, 0x61, 0x74,
	0x65, 0x12, 0x28, 0x0a, 0x0d, 0x72, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x5f, 0x6d, 0x6f,
	0x64, 0x65, 0x18, 0x06, 0x20, 0x01, 0x28, 0x09, 0x48, 0x00, 0x52, 0x0c, 0x72, 0x65, 0x73, 0x70,
	0x6f, 0x6e, 0x73, 0x65, 0x4d, 0x6f, 0x64, 0x65, 0x88, 0x01, 0x01, 0x12, 0x14, 0x0a, 0x05, 0x6e,
	0x6f, 0x6e, 0x63, 0x65, 0x18, 0x07, 0x20, 0x01, 0x28, 0x09, 0x52, 0x05, 0x6e, 0x6f, 0x6e, 0x63,
	0x65, 0x12, 0x1d, 0x0a, 0x07, 0x64, 0x69, 0x73, 0x70, 0x6c, 0x61, 0x79, 0x18, 0x08, 0x20, 0x01,
	0x28, 0x09, 0x48, 0x01, 0x52, 0x07, 0x64, 0x69, 0x73, 0x70, 0x6c, 0x61, 0x79, 0x88, 0x01, 0x01,
	0x12, 0x1b, 0x0a, 0x06, 0x70, 0x72, 0x6f, 0x6d, 0x70, 0x74, 0x18, 0x09, 0x20, 0x01, 0x28, 0x09,
	0x48, 0x02, 0x52, 0x06, 0x70, 0x72, 0x6f, 0x6d, 0x70, 0x74, 0x88, 0x01, 0x01, 0x12, 0x1c, 0x0a,
	0x07, 0x6d, 0x61, 0x78, 0x5f, 0x61, 0x67, 0x65, 0x18, 0x0a, 0x20, 0x01, 0x28, 0x04, 0x48, 0x03,
	0x52, 0x06, 0x6d, 0x61, 0x78, 0x41, 0x67, 0x65, 0x88, 0x01, 0x01, 0x12, 0x22, 0x0a, 0x0a, 0x75,
	0x69, 0x5f, 0x6c, 0x6f, 0x63, 0x61, 0x6c, 0x65, 0x73, 0x18, 0x0b, 0x20, 0x01, 0x28, 0x09, 0x48,
	0x04, 0x52, 0x09, 0x75, 0x69, 0x4c, 0x6f, 0x63, 0x61, 0x6c, 0x65, 0x73, 0x88, 0x01, 0x01, 0x12,
	0x27, 0x0a, 0x0d, 0x69, 0x64, 0x5f, 0x74, 0x6f, 0x6b, 0x65, 0x6e, 0x5f, 0x68, 0x69, 0x6e, 0x74,
	0x18, 0x0c, 0x20, 0x01, 0x28, 0x09, 0x48, 0x05, 0x52, 0x0b, 0x69, 0x64, 0x54, 0x6f, 0x6b, 0x65,
	0x6e, 0x48, 0x69, 0x6e, 0x74, 0x88, 0x01, 0x01, 0x12, 0x22, 0x0a, 0x0a, 0x61, 0x63, 0x72, 0x5f,
	0x76, 0x61, 0x6c, 0x75, 0x65, 0x73, 0x18, 0x0d, 0x20, 0x01, 0x28, 0x09, 0x48, 0x06, 0x52, 0x09,
	0x61, 0x63, 0x72, 0x56, 0x61, 0x6c, 0x75, 0x65, 0x73, 0x88, 0x01, 0x01, 0x12, 0x1d, 0x0a, 0x07,
	0x72, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x18, 0x0e, 0x20, 0x01, 0x28, 0x09, 0x48, 0x07, 0x52,
	0x07, 0x72, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x88, 0x01, 0x01, 0x12, 0x24, 0x0a, 0x0b, 0x72,
	0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x5f, 0x75, 0x72, 0x69, 0x18, 0x0f, 0x20, 0x01, 0x28, 0x09,
	0x48, 0x08, 0x52, 0x0a, 0x72, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x55, 0x72, 0x69, 0x88, 0x01,
	0x01, 0x12, 0x25, 0x0a, 0x0e, 0x63, 0x6f, 0x64, 0x65, 0x5f, 0x63, 0x68, 0x61, 0x6c, 0x6c, 0x65,
	0x6e, 0x67, 0x65, 0x18, 0x10, 0x20, 0x01, 0x28, 0x09, 0x52, 0x0d, 0x63, 0x6f, 0x64, 0x65, 0x43,
	0x68, 0x61, 0x6c, 0x6c, 0x65, 0x6e, 0x67, 0x65, 0x12, 0x32, 0x0a, 0x15, 0x63, 0x6f, 0x64, 0x65,
	0x5f, 0x63, 0x68, 0x61, 0x6c, 0x6c, 0x65, 0x6e, 0x67, 0x65, 0x5f, 0x6d, 0x65, 0x74, 0x68, 0x6f,
	0x64, 0x18, 0x11, 0x20, 0x01, 0x28, 0x09, 0x52, 0x13, 0x63, 0x6f, 0x64, 0x65, 0x43, 0x68, 0x61,
	0x6c, 0x6c, 0x65, 0x6e, 0x67, 0x65, 0x4d, 0x65, 0x74, 0x68, 0x6f, 0x64, 0x12, 0x1a, 0x0a, 0x08,
	0x61, 0x75, 0x64, 0x69, 0x65, 0x6e, 0x63, 0x65, 0x18, 0x12, 0x20, 0x01, 0x28, 0x09, 0x52, 0x08,
	0x61, 0x75, 0x64, 0x69, 0x65, 0x6e, 0x63, 0x65, 0x12, 0x22, 0x0a, 0x0a, 0x64, 0x70, 0x6f, 0x70,
	0x5f, 0x70, 0x72, 0x6f, 0x6f, 0x66, 0x18, 0x13, 0x20, 0x01, 0x28, 0x09, 0x48, 0x09, 0x52, 0x09,
	0x64, 0x70, 0x6f, 0x70, 0x50, 0x72, 0x6f, 0x6f, 0x66, 0x88, 0x01, 0x01, 0x12, 0x1a, 0x0a, 0x08,
	0x72, 0x65, 0x73, 0x6f, 0x75, 0x72, 0x63, 0x65, 0x18, 0x14, 0x20, 0x03, 0x28, 0x09, 0x52, 0x08,
	0x72, 0x65, 0x73, 0x6f, 0x75, 0x72, 0x63, 0x65, 0x12, 0x15, 0x0a, 0x03, 0x69, 0x73, 0x73, 0x18,
	0x15, 0x20, 0x01, 0x28, 0x09, 0x48, 0x0a, 0x52, 0x03, 0x69, 0x73, 0x73, 0x88, 0x01, 0x01, 0x12,
	0x2d, 0x0a, 0x10, 0x6c, 0x6f, 0x67, 0x69, 0x6e, 0x5f, 0x68, 0x69, 0x6e, 0x74, 0x5f, 0x74, 0x6f,
	0x6b, 0x65, 0x6e, 0x18, 0x16, 0x20, 0x01, 0x28, 0x09, 0x48, 0x0b, 0x52, 0x0e, 0x6c, 0x6f, 0x67,
	0x69, 0x6e, 0x48, 0x69, 0x6e, 0x74, 0x54, 0x6f, 0x6b, 0x65, 0x6e, 0x88, 0x01, 0x01, 0x12, 0x22,
	0x0a, 0x0a, 0x6c, 0x6f, 0x67, 0x69, 0x6e, 0x5f, 0x68, 0x69, 0x6e, 0x74, 0x18, 0x17, 0x20, 0x01,
	0x28, 0x09, 0x48, 0x0c, 0x52, 0x09, 0x6c, 0x6f, 0x67, 0x69, 0x6e, 0x48, 0x69, 0x6e, 0x74, 0x88,
	0x01, 0x01, 0x42, 0x10, 0x0a, 0x0e, 0x5f, 0x72, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x5f,
	0x6d, 0x6f, 0x64, 0x65, 0x42, 0x0a, 0x0a, 0x08, 0x5f, 0x64, 0x69, 0x73, 0x70, 0x6c, 0x61, 0x79,
	0x42, 0x09, 0x0a, 0x07, 0x5f, 0x70, 0x72, 0x6f, 0x6d, 0x70, 0x74, 0x42, 0x0a, 0x0a, 0x08, 0x5f,
	0x6d, 0x61, 0x78, 0x5f, 0x61, 0x67, 0x65, 0x42, 0x0d, 0x0a, 0x0b, 0x5f, 0x75, 0x69, 0x5f, 0x6c,
	0x6f, 0x63, 0x61, 0x6c, 0x65, 0x73, 0x42, 0x10, 0x0a, 0x0e, 0x5f, 0x69, 0x64, 0x5f, 0x74, 0x6f,
	0x6b, 0x65, 0x6e, 0x5f, 0x68, 0x69, 0x6e, 0x74, 0x42, 0x0d, 0x0a, 0x0b, 0x5f, 0x61, 0x63, 0x72,
	0x5f, 0x76, 0x61, 0x6c, 0x75, 0x65, 0x73, 0x42, 0x0a, 0x0a, 0x08, 0x5f, 0x72, 0x65, 0x71, 0x75,
	0x65, 0x73, 0x74, 0x42, 0x0e, 0x0a, 0x0c, 0x5f, 0x72, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x5f,
	0x75, 0x72, 0x69, 0x42, 0x0d, 0x0a, 0x0b, 0x5f, 0x64, 0x70, 0x6f, 0x70, 0x5f, 0x70, 0x72, 0x6f,
	0x6f, 0x66, 0x42, 0x06, 0x0a, 0x04, 0x5f, 0x69, 0x73, 0x73, 0x42, 0x13, 0x0a, 0x11, 0x5f, 0x6c,
	0x6f, 0x67, 0x69, 0x6e, 0x5f, 0x68, 0x69, 0x6e, 0x74, 0x5f, 0x74, 0x6f, 0x6b, 0x65, 0x6e, 0x42,
	0x0d, 0x0a, 0x0b, 0x5f, 0x6c, 0x6f, 0x67, 0x69, 0x6e, 0x5f, 0x68, 0x69, 0x6e, 0x74, 0x42, 0x96,
	0x01, 0x0a, 0x10, 0x63, 0x6f, 0x6d, 0x2e, 0x6f, 0x69, 0x64, 0x63, 0x2e, 0x66, 0x6c, 0x6f, 0x77,
	0x2e, 0x76, 0x31, 0x42, 0x09, 0x46, 0x6c, 0x6f, 0x77, 0x50, 0x72, 0x6f, 0x74, 0x6f, 0x50, 0x01,
	0x5a, 0x25, 0x7a, 0x6e, 0x74, 0x72, 0x2e, 0x69, 0x6f, 0x2f, 0x73, 0x6f, 0x6c, 0x69, 0x64, 0x2f,
	0x61, 0x70, 0x69, 0x2f, 0x6f, 0x69, 0x64, 0x63, 0x2f, 0x66, 0x6c, 0x6f, 0x77, 0x2f, 0x76, 0x31,
	0x3b, 0x66, 0x6c, 0x6f, 0x77, 0x76, 0x31, 0xa2, 0x02, 0x03, 0x4f, 0x46, 0x58, 0xaa, 0x02, 0x0c,
	0x4f, 0x69, 0x64, 0x63, 0x2e, 0x46, 0x6c, 0x6f, 0x77, 0x2e, 0x56, 0x31, 0xca, 0x02, 0x0c, 0x4f,
	0x69, 0x64, 0x63, 0x5c, 0x46, 0x6c, 0x6f, 0x77, 0x5c, 0x56, 0x31, 0xe2, 0x02, 0x18, 0x4f, 0x69,
	0x64, 0x63, 0x5c, 0x46, 0x6c, 0x6f, 0x77, 0x5c, 0x56, 0x31, 0x5c, 0x47, 0x50, 0x42, 0x4d, 0x65,
	0x74, 0x61, 0x64, 0x61, 0x74, 0x61, 0xea, 0x02, 0x0e, 0x4f, 0x69, 0x64, 0x63, 0x3a, 0x3a, 0x46,
	0x6c, 0x6f, 0x77, 0x3a, 0x3a, 0x56, 0x31, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_oidc_flow_v1_flow_proto_rawDescOnce sync.Once
	file_oidc_flow_v1_flow_proto_rawDescData = file_oidc_flow_v1_flow_proto_rawDesc
)

func file_oidc_flow_v1_flow_proto_rawDescGZIP() []byte {
	file_oidc_flow_v1_flow_proto_rawDescOnce.Do(func() {
		file_oidc_flow_v1_flow_proto_rawDescData = protoimpl.X.CompressGZIP(file_oidc_flow_v1_flow_proto_rawDescData)
	})
	return file_oidc_flow_v1_flow_proto_rawDescData
}

var file_oidc_flow_v1_flow_proto_msgTypes = make([]protoimpl.MessageInfo, 1)
var file_oidc_flow_v1_flow_proto_goTypes = []interface{}{
	(*AuthorizationRequest)(nil), // 0: oidc.flow.v1.AuthorizationRequest
}
var file_oidc_flow_v1_flow_proto_depIdxs = []int32{
	0, // [0:0] is the sub-list for method output_type
	0, // [0:0] is the sub-list for method input_type
	0, // [0:0] is the sub-list for extension type_name
	0, // [0:0] is the sub-list for extension extendee
	0, // [0:0] is the sub-list for field type_name
}

func init() { file_oidc_flow_v1_flow_proto_init() }
func file_oidc_flow_v1_flow_proto_init() {
	if File_oidc_flow_v1_flow_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_oidc_flow_v1_flow_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*AuthorizationRequest); i {
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
	file_oidc_flow_v1_flow_proto_msgTypes[0].OneofWrappers = []interface{}{}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_oidc_flow_v1_flow_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   1,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_oidc_flow_v1_flow_proto_goTypes,
		DependencyIndexes: file_oidc_flow_v1_flow_proto_depIdxs,
		MessageInfos:      file_oidc_flow_v1_flow_proto_msgTypes,
	}.Build()
	File_oidc_flow_v1_flow_proto = out.File
	file_oidc_flow_v1_flow_proto_rawDesc = nil
	file_oidc_flow_v1_flow_proto_goTypes = nil
	file_oidc_flow_v1_flow_proto_depIdxs = nil
}
