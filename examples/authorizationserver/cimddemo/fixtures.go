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

// Package cimddemo carries the static fixtures of the CIMD example client
// (draft-ietf-oauth-client-id-metadata-document): the Client ID Metadata
// Document served for the https://cimd.example.org/client identifier and the
// fixed signing seed it references, so the example authorization server and
// the cimdclient demo agree without external infrastructure. The document is
// resolved through the real cimd.Resolver path; only the transport is
// in-memory because the hardened httpfetch refuses loopback destinations by
// SSRF pre-flight.
package cimddemo

import (
	"context"

	"zntr.io/solid/sdk/cimd"
	"zntr.io/solid/server/storage"
)

// ClientIdentifierURL is the demo CIMD client identifier. It MUST match the
// document client_id by simple string comparison (draft section 4) and MUST
// be a valid Client Identifier URL (draft section 3).
const ClientIdentifierURL = "https://cimd.example.org/client"

// ClientSeedB64 is the base64url ML-DSA-65 seed of the demo client signing
// key. It is a published example fixture, not production key material.
const ClientSeedB64 = "c29saWQtY2ltZC1leGFtcGxlLWNsaWVudC1maXh0dXI"

// ClientPubB64 is the base64url ML-DSA-65 public key of the demo client,
// derived from ClientSeedB64; it matches the "pub" member of the JWKS
// published in the demo document.
const ClientPubB64 = "QmzQeeu3NSgWxoWbpsJS4iJRYF18i7QwosMdc0P36w2mz52OHheXdYexfdImEUf84O88ONHV15JyY4F_Egk80NtXbxLGe46HqE2vq7yLuIR6qFX0l9CFcrT6tyRSy5Fh6iNQ4dRuQqhjzyfUASNjp_LR20kKzHQMlc3e3sfPUQNPsV-tqSXKf7gnawMF9Y-mWVLYsoxekClmITUTujvuAYL7zOzWmRXKqEJT_3OC_htroqh1f3DqJJGmrLVYMRGQciElYk5QZKomBaBucSHM2gUAWZnJkLAJi8mRM0kyDimIaFlCr15JE5El6SUX8DniuOowb95wKn4QtT4UhiqR65TuhMZKsWKDg5Rx9uSRWGeV_2sjc6BzCnTeHRe-rvP3LahV8GkNTLfad5KYVUdHpi2om1anv-l7h6kbAHEeGZk3qZObUfCVNa0wF4hUL81OjjniWEiucSPA8OxsFRniO-jqXKIgL5kSoDaqPdI7uMgQAQ0JN9Eol51NgQXb6jXwE0cXznXGCe4OCzdNDEYJ4hIcLnLMgnsbNXVcY-wXw3cyy17TmR23j6qw6ZtPhOWHMyrmtaa-_QwFT4IvCdby1eiwmwO3VautjxFdt5ndM_X2ihAwtOZo9LzQ6RA_JU3eSM_PCCMRZR-XFR7FQCMq7mhSPcQa21JFLXcWwVGtBn67-2fMxq9TnVVI1Hc6KAmialK-6K5p3Z1hY2chGiYKgV9yDpRwBD44bjE509DJn0Hd-jG2AhsxWGAD-HGduymElI18gtZ5rWvt0Y2mV5CnIG2BcSzMO2uVxCVl57liiDU1KXAiiLvu0i8SBPPgvp6V5ImpIwM3FdzMEv2sUC5rgtkxwvAW3XrTjpGCO4uFyOVYTMKleeY1TP25yDECCXZExdr-ZWXYjpDHlvBQwghAl9FrCCGYY_VC0z3QhlxhNRK17ppJ_-U5_lm1Tm-rr-MgkkhfcE1bB2yljEQTa_6uCwwdWZBeCYtPcjWf14-qkRTtAuRFaUOMOnTVnpcIZoOrs5DRt5y4hMkKk9S497dNEbe8GBxO6XbCdybzHznmFLiCP6SG5HPFVt36PHlcimQ_3GEaOikNUSEhWICfwu-HY26Q2f1nC5-nQ6O1oqSny2jV4Ft7uN5TXdCKZ4iu8wAhvwvOe49molEpzglRIkZF6RZeBe-en7uHAwUtlsXqHbhE1XWG9manJyPLcYnw-ukk1AzvC-YzJE2US3EgRFNMfnVXzU4JuotMo88i4_JjbpPmNnDsJbAtY7VnCZtu_I9Ab0xqDyFi7IbOhkccx5Z-77uEx7kg5zSWSdV_QE6WK25PMHQk3pLpybeUm_kAdBg0dIjm0ANIEUmYTobFDbDB1M2ywRaW9TixZ3rwVxR5zQAJdC6yacCrWraL0Hny-Krt_UUUDJoAOfMezwiOGTaycqG0oRlC7i48D6wE13XOI6IzWTjDmuVKcIefrVfRBylX7YU0m68mIK2wUZDEqINCIVtW0MrazEwfp57UJsAZkEidfFLcbWlj4-Gc-sv-1jN7Ms0ZCvPfTH3crQMX3gev9PGIF7SK5NniDlJ4q393U52wFmgie-VjCfsHFyw2_MAT3TNrkZm1qZXniWgkOK5p1Zd3dY0Nan-1RPmEyuprlgjfbW8m5sVLeGHz3hGzhZjG6_p-FeveckBHSA5oIHDZ09xE5y-R2jhQiEnZqe_1PMymAdah_XDrweIF4FPmGPA6T1fTCUjDAlP2CnIv7SnzJkRUwJ4CgBsy5bBcaEjhM7PrwodSXyv82WT2MaWHii2HlsC2ZEr6NWJrOP7Zgz5o8p8zwPFBxnSNLb3dkEtdo3d3rTZatafHrANaL-KwrlxXXlPIIdnsYnth6FKYae804pXi7Y_9qcTd4mr0_b5MOzFOkdzoJUKdFlLiCYAcXIeTpejifTgSstpZ0v2JjeIFXgmWp8RltB9_gQ-vihs6JXSQbNqkoAI9v3N5p70cJSYBIVVSXFqSdGDjpGQu0BjtVG_zNn6IijtMs-ocY0u570a1WhnnLSIzRvuc3jJ5VVlEfAvJVeyPy1nXdVGH47Gn2p3cBctTbz-k6Qb1XnY0f0QXEWJYyPfvQBLLgrFe4LwRSnqWGnmTHGmW1duu9z3q2_3aoxBya_HtAIaa5W41awbYbdzeeOqW2UO9944cetSOz2UwtqEh8pAHZ0iFB7vlwZ2R2vxp-wg4tTkpX4KaCnrhtjWwkMRu4NeuZ4OBOK7sXpK8qYo2E3RMurzDsrUgdjBMIDShIo_ZFkRUMbMe0BEwCxAT_-YY4PepZN_zuHG2nbgRQkfU2g7gxQ2rA5RR0HfTG0RTe6ApqF3SUrPIy6r7bJuxCXev0-1m5HsTRwmToEEmEyVVSe0GVrLw2faI25AEU7XL5To0mc101x5KPZqT4kguk74PTtyXTc0vczI1quhKezYZ7JnDQpVugPov0x_VdCeoHUVEu59Eo4vNFCsQIGL6rF_ICsTwGcOkjYz4lwsX0pr_hRscNi8oY9NZ0GZFqOQ4WMwaXS2SsuE2MtgnEJGbFgj_zAavg6ocCdFq77Eg9QIY54-SLUjiYD8SVOMg3kgZGfjVbiXnHlgITIU"

// DocumentBody is the raw Client ID Metadata Document JSON served for the
// demo identifier. It declares private_key_jwt authentication with the
// client's ML-DSA-65 public key (no private material, draft section 4.1) and
// authorizes the example resource server to introspect the client's tokens
// (RFC 7662 section 2.1 authorized_introspection_clients).
const DocumentBody = `{"client_id":"https://cimd.example.org/client","client_name":"cimd-example-client","token_endpoint_auth_method":"private_key_jwt","grant_types":["client_credentials"],"jwks":{"keys":[{"kty":"AKP","alg":"ML-DSA-65","use":"sig","kid":"https://cimd.example.org/client","pub":"QmzQeeu3NSgWxoWbpsJS4iJRYF18i7QwosMdc0P36w2mz52OHheXdYexfdImEUf84O88ONHV15JyY4F_Egk80NtXbxLGe46HqE2vq7yLuIR6qFX0l9CFcrT6tyRSy5Fh6iNQ4dRuQqhjzyfUASNjp_LR20kKzHQMlc3e3sfPUQNPsV-tqSXKf7gnawMF9Y-mWVLYsoxekClmITUTujvuAYL7zOzWmRXKqEJT_3OC_htroqh1f3DqJJGmrLVYMRGQciElYk5QZKomBaBucSHM2gUAWZnJkLAJi8mRM0kyDimIaFlCr15JE5El6SUX8DniuOowb95wKn4QtT4UhiqR65TuhMZKsWKDg5Rx9uSRWGeV_2sjc6BzCnTeHRe-rvP3LahV8GkNTLfad5KYVUdHpi2om1anv-l7h6kbAHEeGZk3qZObUfCVNa0wF4hUL81OjjniWEiucSPA8OxsFRniO-jqXKIgL5kSoDaqPdI7uMgQAQ0JN9Eol51NgQXb6jXwE0cXznXGCe4OCzdNDEYJ4hIcLnLMgnsbNXVcY-wXw3cyy17TmR23j6qw6ZtPhOWHMyrmtaa-_QwFT4IvCdby1eiwmwO3VautjxFdt5ndM_X2ihAwtOZo9LzQ6RA_JU3eSM_PCCMRZR-XFR7FQCMq7mhSPcQa21JFLXcWwVGtBn67-2fMxq9TnVVI1Hc6KAmialK-6K5p3Z1hY2chGiYKgV9yDpRwBD44bjE509DJn0Hd-jG2AhsxWGAD-HGduymElI18gtZ5rWvt0Y2mV5CnIG2BcSzMO2uVxCVl57liiDU1KXAiiLvu0i8SBPPgvp6V5ImpIwM3FdzMEv2sUC5rgtkxwvAW3XrTjpGCO4uFyOVYTMKleeY1TP25yDECCXZExdr-ZWXYjpDHlvBQwghAl9FrCCGYY_VC0z3QhlxhNRK17ppJ_-U5_lm1Tm-rr-MgkkhfcE1bB2yljEQTa_6uCwwdWZBeCYtPcjWf14-qkRTtAuRFaUOMOnTVnpcIZoOrs5DRt5y4hMkKk9S497dNEbe8GBxO6XbCdybzHznmFLiCP6SG5HPFVt36PHlcimQ_3GEaOikNUSEhWICfwu-HY26Q2f1nC5-nQ6O1oqSny2jV4Ft7uN5TXdCKZ4iu8wAhvwvOe49molEpzglRIkZF6RZeBe-en7uHAwUtlsXqHbhE1XWG9manJyPLcYnw-ukk1AzvC-YzJE2US3EgRFNMfnVXzU4JuotMo88i4_JjbpPmNnDsJbAtY7VnCZtu_I9Ab0xqDyFi7IbOhkccx5Z-77uEx7kg5zSWSdV_QE6WK25PMHQk3pLpybeUm_kAdBg0dIjm0ANIEUmYTobFDbDB1M2ywRaW9TixZ3rwVxR5zQAJdC6yacCrWraL0Hny-Krt_UUUDJoAOfMezwiOGTaycqG0oRlC7i48D6wE13XOI6IzWTjDmuVKcIefrVfRBylX7YU0m68mIK2wUZDEqINCIVtW0MrazEwfp57UJsAZkEidfFLcbWlj4-Gc-sv-1jN7Ms0ZCvPfTH3crQMX3gev9PGIF7SK5NniDlJ4q393U52wFmgie-VjCfsHFyw2_MAT3TNrkZm1qZXniWgkOK5p1Zd3dY0Nan-1RPmEyuprlgjfbW8m5sVLeGHz3hGzhZjG6_p-FeveckBHSA5oIHDZ09xE5y-R2jhQiEnZqe_1PMymAdah_XDrweIF4FPmGPA6T1fTCUjDAlP2CnIv7SnzJkRUwJ4CgBsy5bBcaEjhM7PrwodSXyv82WT2MaWHii2HlsC2ZEr6NWJrOP7Zgz5o8p8zwPFBxnSNLb3dkEtdo3d3rTZatafHrANaL-KwrlxXXlPIIdnsYnth6FKYae804pXi7Y_9qcTd4mr0_b5MOzFOkdzoJUKdFlLiCYAcXIeTpejifTgSstpZ0v2JjeIFXgmWp8RltB9_gQ-vihs6JXSQbNqkoAI9v3N5p70cJSYBIVVSXFqSdGDjpGQu0BjtVG_zNn6IijtMs-ocY0u570a1WhnnLSIzRvuc3jJ5VVlEfAvJVeyPy1nXdVGH47Gn2p3cBctTbz-k6Qb1XnY0f0QXEWJYyPfvQBLLgrFe4LwRSnqWGnmTHGmW1duu9z3q2_3aoxBya_HtAIaa5W41awbYbdzeeOqW2UO9944cetSOz2UwtqEh8pAHZ0iFB7vlwZ2R2vxp-wg4tTkpX4KaCnrhtjWwkMRu4NeuZ4OBOK7sXpK8qYo2E3RMurzDsrUgdjBMIDShIo_ZFkRUMbMe0BEwCxAT_-YY4PepZN_zuHG2nbgRQkfU2g7gxQ2rA5RR0HfTG0RTe6ApqF3SUrPIy6r7bJuxCXev0-1m5HsTRwmToEEmEyVVSe0GVrLw2faI25AEU7XL5To0mc101x5KPZqT4kguk74PTtyXTc0vczI1quhKezYZ7JnDQpVugPov0x_VdCeoHUVEu59Eo4vNFCsQIGL6rF_ICsTwGcOkjYz4lwsX0pr_hRscNi8oY9NZ0GZFqOQ4WMwaXS2SsuE2MtgnEJGbFgj_zAavg6ocCdFq77Eg9QIY54-SLUjiYD8SVOMg3kgZGfjVbiXnHlgITIU"}]},"authorized_introspection_clients":["5stz52n91hr7aw9q1h5hbuvkt2ovevdw"]}`

// StaticFetcher serves the document body from memory, standing in for the
// https endpoint that would host it in a real deployment. The resolution path
// (identifier validation, document decoding, section 4.1 restrictions,
// mapping to the internal Client) is the real one.
func StaticFetcher() cimd.Fetcher {
	return staticFetcher{}
}

type staticFetcher struct{}

// Fetch implements cimd.Fetcher.
func (staticFetcher) Fetch(_ context.Context, clientIdentifierURL string) ([]byte, error) {
	if clientIdentifierURL != ClientIdentifierURL {
		return nil, storage.ErrNotFound
	}
	return []byte(DocumentBody), nil
}
