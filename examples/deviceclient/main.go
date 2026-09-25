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

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"zntr.io/solid/client"
	"zntr.io/solid/sdk/dpop"
	"zntr.io/solid/sdk/jwk"
	"zntr.io/solid/sdk/token/jwt"
)

func main() {
	ctx := context.Background()

	// Create OIDC client instance
	oidcClient, err := client.HTTP(ctx, "http://127.0.0.1:8080", &client.Options{
		ClientID: "t8p9duw4n2klximkv3kagaud796ul67g",
		JWK:      []byte(`{"alg":"ML-DSA-65","d":"c29saWQtZGV2Y2wtc2VlZC0wMDAwMDAwMDAwMDAwMTE","kid":"t8p9duw4n2klximkv3kagaud796ul67g","kty":"AKP","pub":"CWCYiJcLgTn3MOTS7GtvSdgqiRmKCtSqTK6NHiuYoNzokAu3a9wpmg7x_chj3BsUuGywDB-gIcKMvarLoOUibIr-m59GAcZzwRUBpWUBGp3nFQmvT51Zsw_Za17NmBbVKK4dfgTMbIFYJU9vnHSd-PasyFLZN8H6SVzFNdSd5yjjbtUeLNa3YIBCD1V6ug9h2FO7Aw96oxMTCjh9-OCtbjFmoSlhboSGUrNYCxYVWS5Fn-xpP1fvdHAoV5stztT5MIXxAfKzw7PLw9eeayZnjKk-DLL_UJeRxr4ICxJCwS3T0j6ApoMrap0UnOHza1ye0mG8t431udH5Xi8qfQJXOQPFYxSzA36rfus5IMQikB4wJvhm3xrOlkJaJai-TjqWbAdGzafX57wdnxkfDK3qejQZN_vBEmMU1WasfB-IIDkSDu_QEq1YNEeRpQQRDRLEXV57KDAGZce3HEWq5KUf62sYL2Hepc-gGYVmoKg0w6bmRjSg55ta5MTLooNIyzBDaULxT2JHxZjEnRiuQKAhToNYnvdf7irzVdqEJ9Op09y-Ft6W1Y7B02g2bbyP0tgnDh8LosB1hCNz4sRV59K7FFyAFlSYwkCTtTX3GinJwyiltuNljFQd2rgwOQnZTL820O8_cO0puiaibiDDWHfC95OYH293JfanyBvIfSCgwYTfegeiAMD5WxfJb3v7uYMrOrYZdzay7lbzWazX-h7t9HCZZly6IEDkngD4HOJpCRMKsTeUi6g7iB2yah3sb0fmHozjMkCHJw5hUPSkVbRbHtJj36AavNgtaz7gYsbxntYbQPeN1bNlMnFK0lXKC8ALH9i3BruztCGFsGKQh_FuPu_CIh-vHEDmNJZc4H41zvylj3Or7d3ueNQa2u9aOf7pSNsg4EG24HRp5N-9MoUoIncig1tHogoNbrGu5VRJLaO5TphAsmvs4Z32cOlKW6nmi1axOTmfYTy53guvwWYpFXSiLKoKRxQ5pPXVimmlbUOn9M-6gF1_V1nmNtMK7O7asJGZDFiiSTg0pD3RVqhTKtcvlppD_AoGo2IptsYSe4bzRyJ_USD7VlmL6US61tfsrDk_HHdGUGd_mdfKL97O5dkNJ5MzTzUTQQ2TwS8GFI_EknS2SkwfDWu7Q-ZhUoXO25mSmPcjWIfaUphhypG1HAUUgP2mfIBLNn6FzInU4MCxdZ1tTjm25k-KV0sQVGxRatQ5W6bjG2H6rFiMBZCWtXZVMJQVYg4lri9W2dErgqnSpDlakUVhF6CiCyrXDyvp3HzPB7RETffRKn69AzB-9KPgkFrSoYDBkZ4kSz1D3D2DQJRJl6xiJzeVVUlj8BQFnZx63EPrDl8Mvn33NmTV8RyBvnbWPJ4daa0KSNP6m_OUjh6fQhLtwTtVYUYSqsyNfNhdmgXSPXCaUQmerGUAGS33jryzvV6kdJ7An3zVcGOu7ZP6AGfDkkeoDLdOuTLeqWcwhw9ZbLJY5ee5KVFj8viM19kW-jhYeJZHntSjetrEmCmJ131fDEc71LsKwwNLJE92nYsRIghkImpQMhTxtIXjgJ-JRaH9tpWkPcL6P6FAKoGFTWJ0uxlsnEQEg3ad-cwh6bNh_9ramKzdU1MK93ixIw1NgfLniXzsfnJWLdcPR1JtDSu8BUXn6qoWolR9qzncGZi22CQ6DK7i6i53SGSTG2FBezdmtQIPpeOrDQnP_ZVnU5z5TDXzvbF9P_b2znMR8XhP4mCA7_Tb-od5gB4a1E5QZ-lJyeVOx537c9iag72TvAU6HA9V0inUInTxkkK8gYQvrTo8PXTu8Fos7axl8N_ZDV7UGYEluuMxR4K9pnbL-mV7-c-dpM9D1Tx-eFvYwNIXhSWwYJ7GwN2vt2438jnEHHS39pNygnhHRerUt7NL6nIRdl2pDXVqPBu0MHO0H2LKC4yrET3Ps-fbv6f-ZR7ZC2bfhOVlqrjDn8IGyjVs-_1asuToQmMFuRESCYMPlI3wHOdqQGIKKmqDfQqRnQiiC4K8V1hZdMj4wLJRKIVsScOlkK0lFXW8eX6XuuRI3oVWdLj_qE72yax8_WtWxntX1N6lAF745OubzW81Mf4l2UNT5A4tystsDKyCoA3ifDvNyCEUIDn8Fe5RxHBIpRL5_vC6RD5PdyW-vY3ZITJzw-yJ0DjdUD5KwKv6yJGvlx0VfHK-RJ22ooAiQgtkwyF-X8zp7tr4LMCJOF4ighmupfEySVDszlwuKK-DZnAGV0lzcfLI4LEoeSfCbxqWTsjoC2doWj7rs0SXYJRsF4XXpq_o_1fffub0wtLdIeI8b8Z1Qv8NTKOKO1NyRjBjZan2U4hbucfxLqP3zPj9NkmiXAoP6nMZ9IWT_Rn7ycR4v7yCFUPHyGWZZJl7e_OAhDhnrozpK55Sl9z4f64xEAoBtYHUovAhaILBxxNlq9mPgV7nzRLnyxTxZUy4-gMCvN5TKGT3cQc4LHwXP4O3jkRIVmov44CZ7EkYssp9k-rrZ527TEYa_tygsCupdsbChidOhdVWCk9PSK_VTomWHlbYXoFOUiqzOpekWOws71LSuNHwFybQ4djz4xfKKU-HwXb5Jpca7y04ZCxQ__w","use":"sig"}`),
		Scopes:   []string{"openid"},
		Audience: "http://localhost:8085",
	})
	if err != nil {
		panic(err)
	}

	// Create client assertion
	assertion, err := oidcClient.Assertion()
	if err != nil {
		panic(err)
	}

	// The fixture client requires DPoP-bound access tokens: mint a proof
	// with the client's ML-DSA key and drive the token request manually.
	dpopKeySet, err := jwk.Parse([]byte(`{"kty":"AKP","alg":"ML-DSA-65","kid":"t8p9duw4n2klximkv3kagaud796ul67g","use":"sig","pub":"CWCYiJcLgTn3MOTS7GtvSdgqiRmKCtSqTK6NHiuYoNzokAu3a9wpmg7x_chj3BsUuGywDB-gIcKMvarLoOUibIr-m59GAcZzwRUBpWUBGp3nFQmvT51Zsw_Za17NmBbVKK4dfgTMbIFYJU9vnHSd-PasyFLZN8H6SVzFNdSd5yjjbtUeLNa3YIBCD1V6ug9h2FO7Aw96oxMTCjh9-OCtbjFmoSlhboSGUrNYCxYVWS5Fn-xpP1fvdHAoV5stztT5MIXxAfKzw7PLw9eeayZnjKk-DLL_UJeRxr4ICxJCwS3T0j6ApoMrap0UnOHza1ye0mG8t431udH5Xi8qfQJXOQPFYxSzA36rfus5IMQikB4wJvhm3xrOlkJaJai-TjqWbAdGzafX57wdnxkfDK3qejQZN_vBEmMU1WasfB-IIDkSDu_QEq1YNEeRpQQRDRLEXV57KDAGZce3HEWq5KUf62sYL2Hepc-gGYVmoKg0w6bmRjSg55ta5MTLooNIyzBDaULxT2JHxZjEnRiuQKAhToNYnvdf7irzVdqEJ9Op09y-Ft6W1Y7B02g2bbyP0tgnDh8LosB1hCNz4sRV59K7FFyAFlSYwkCTtTX3GinJwyiltuNljFQd2rgwOQnZTL820O8_cO0puiaibiDDWHfC95OYH293JfanyBvIfSCgwYTfegeiAMD5WxfJb3v7uYMrOrYZdzay7lbzWazX-h7t9HCZZly6IEDkngD4HOJpCRMKsTeUi6g7iB2yah3sb0fmHozjMkCHJw5hUPSkVbRbHtJj36AavNgtaz7gYsbxntYbQPeN1bNlMnFK0lXKC8ALH9i3BruztCGFsGKQh_FuPu_CIh-vHEDmNJZc4H41zvylj3Or7d3ueNQa2u9aOf7pSNsg4EG24HRp5N-9MoUoIncig1tHogoNbrGu5VRJLaO5TphAsmvs4Z32cOlKW6nmi1axOTmfYTy53guvwWYpFXSiLKoKRxQ5pPXVimmlbUOn9M-6gF1_V1nmNtMK7O7asJGZDFiiSTg0pD3RVqhTKtcvlppD_AoGo2IptsYSe4bzRyJ_USD7VlmL6US61tfsrDk_HHdGUGd_mdfKL97O5dkNJ5MzTzUTQQ2TwS8GFI_EknS2SkwfDWu7Q-ZhUoXO25mSmPcjWIfaUphhypG1HAUUgP2mfIBLNn6FzInU4MCxdZ1tTjm25k-KV0sQVGxRatQ5W6bjG2H6rFiMBZCWtXZVMJQVYg4lri9W2dErgqnSpDlakUVhF6CiCyrXDyvp3HzPB7RETffRKn69AzB-9KPgkFrSoYDBkZ4kSz1D3D2DQJRJl6xiJzeVVUlj8BQFnZx63EPrDl8Mvn33NmTV8RyBvnbWPJ4daa0KSNP6m_OUjh6fQhLtwTtVYUYSqsyNfNhdmgXSPXCaUQmerGUAGS33jryzvV6kdJ7An3zVcGOu7ZP6AGfDkkeoDLdOuTLeqWcwhw9ZbLJY5ee5KVFj8viM19kW-jhYeJZHntSjetrEmCmJ131fDEc71LsKwwNLJE92nYsRIghkImpQMhTxtIXjgJ-JRaH9tpWkPcL6P6FAKoGFTWJ0uxlsnEQEg3ad-cwh6bNh_9ramKzdU1MK93ixIw1NgfLniXzsfnJWLdcPR1JtDSu8BUXn6qoWolR9qzncGZi22CQ6DK7i6i53SGSTG2FBezdmtQIPpeOrDQnP_ZVnU5z5TDXzvbF9P_b2znMR8XhP4mCA7_Tb-od5gB4a1E5QZ-lJyeVOx537c9iag72TvAU6HA9V0inUInTxkkK8gYQvrTo8PXTu8Fos7axl8N_ZDV7UGYEluuMxR4K9pnbL-mV7-c-dpM9D1Tx-eFvYwNIXhSWwYJ7GwN2vt2438jnEHHS39pNygnhHRerUt7NL6nIRdl2pDXVqPBu0MHO0H2LKC4yrET3Ps-fbv6f-ZR7ZC2bfhOVlqrjDn8IGyjVs-_1asuToQmMFuRESCYMPlI3wHOdqQGIKKmqDfQqRnQiiC4K8V1hZdMj4wLJRKIVsScOlkK0lFXW8eX6XuuRI3oVWdLj_qE72yax8_WtWxntX1N6lAF745OubzW81Mf4l2UNT5A4tystsDKyCoA3ifDvNyCEUIDn8Fe5RxHBIpRL5_vC6RD5PdyW-vY3ZITJzw-yJ0DjdUD5KwKv6yJGvlx0VfHK-RJ22ooAiQgtkwyF-X8zp7tr4LMCJOF4ighmupfEySVDszlwuKK-DZnAGV0lzcfLI4LEoeSfCbxqWTsjoC2doWj7rs0SXYJRsF4XXpq_o_1fffub0wtLdIeI8b8Z1Qv8NTKOKO1NyRjBjZan2U4hbucfxLqP3zPj9NkmiXAoP6nMZ9IWT_Rn7ycR4v7yCFUPHyGWZZJl7e_OAhDhnrozpK55Sl9z4f64xEAoBtYHUovAhaILBxxNlq9mPgV7nzRLnyxTxZUy4-gMCvN5TKGT3cQc4LHwXP4O3jkRIVmov44CZ7EkYssp9k-rrZ527TEYa_tygsCupdsbChidOhdVWCk9PSK_VTomWHlbYXoFOUiqzOpekWOws71LSuNHwFybQ4djz4xfKKU-HwXb5Jpca7y04ZCxQ__w","d":"c29saWQtZGV2Y2wtc2VlZC0wMDAwMDAwMDAwMDAwMTE"}`))
	if err != nil {
		panic(err)
	}
	dpopKey, _ := dpopKeySet.Key(0)
	prover := dpop.DefaultProver(jwt.DPoPSigner("ML-DSA-65", func(context.Context) (jwk.Key, error) {
		return dpopKey, nil
	}))
	proof, err := prover.Prove("POST", "http://127.0.0.1:8080/token")
	if err != nil {
		panic(err)
	}

	// Retrieve an access token (client_credentials with a DPoP proof).
	params := url.Values{}
	params.Add("grant_type", "client_credentials")
	params.Add("scope", "timestamp:read openid")
	params.Add("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer")
	params.Add("client_assertion", assertion)
	tokenReq, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://127.0.0.1:8080/token", strings.NewReader(params.Encode()))
	if err != nil {
		panic(err)
	}
	tokenReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	tokenReq.Header.Set("DPoP", proof)
	tokenResp, err := http.DefaultClient.Do(tokenReq)
	if err != nil {
		panic(err)
	}
	defer tokenResp.Body.Close()
	var t client.Token
	if err := json.NewDecoder(tokenResp.Body).Decode(&t); err != nil {
		panic(err)
	}
	if t.AccessToken == "" {
		panic("no access token in token response")
	}

	// Let some time to persistence to sync.
	time.Sleep(1000 * time.Millisecond)

	// The access token is DPoP-bound: mint a fresh proof carrying the token
	// value and present it with the DPoP authorization scheme.
	resourceProof, err := prover.Prove("POST", "http://127.0.0.1:8085/", dpop.WithTokenValue(t.AccessToken))
	if err != nil {
		panic(err)
	}

	// Call the timestamp service
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://127.0.0.1:8085", nil)
	if err != nil {
		panic(err)
	}

	// Set the access token value.
	req.Header.Set("Authorization", fmt.Sprintf("DPoP %s", t.AccessToken))
	req.Header.Set("DPoP", resourceProof)

	// Use OAuth2 client
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		panic(err)
	}

	defer resp.Body.Close()
	timestampRaw, err := io.ReadAll(resp.Body)
	if err != nil {
		panic(err)
	}

	fmt.Println(string(timestampRaw))
}
