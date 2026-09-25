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

package inmemory

import (
	"context"
	"strings"

	clientv1 "zntr.io/solid/api/oidc/client/v1"
	"zntr.io/solid/oidc"
	random "zntr.io/solid/sdk/random"
	"zntr.io/solid/server/storage"
)

type clientStorage struct {
	backend map[string]*clientv1.Client
}

// Clients returns a client manager pre-seeded with reference fixtures for
// the example assemblies. This implementation is intended for examples and
// tests only.
func Clients() storage.Client {
	return &clientStorage{
		backend: defaultClients,
	}
}

// defaultClients holds the reference client fixtures used by the example
// assemblies.

// Reference fixture values shared across the example clients.
const (
	fixtureIntrospectionClientID = "5stz52n91hr7aw9q1h5hbuvkt2ovevdw"
	fixtureSectorIdentifier      = "http://127.0.0.1:8085"
	fixtureContactEmail          = "foo@bar.com"
	spiffeMyOAuthClientID        = "spiffe://example.org/my-oauth-client"
	spiffeX509WorkloadID         = "spiffe://example.org/x509-workload"
	spiffeWITWorkloadID          = "spiffe://example.org/wit-workload"
)

var defaultClients = map[string]*clientv1.Client{
	"t8p9duw4n2klximkv3kagaud796ul67g": {
		ClientId:   "t8p9duw4n2klximkv3kagaud796ul67g",
		ClientType: clientv1.ClientType_CLIENT_TYPE_CONFIDENTIAL,
		ClientName: "test-client",
		Jwks: []byte(`{"keys":[
					{
						"kid":"t8p9duw4n2klximkv3kagaud796ul67g",
						"kty":"AKP",
						"alg":"ML-DSA-65",
						"use":"sig",
						"pub":"CWCYiJcLgTn3MOTS7GtvSdgqiRmKCtSqTK6NHiuYoNzokAu3a9wpmg7x_chj3BsUuGywDB-gIcKMvarLoOUibIr-m59GAcZzwRUBpWUBGp3nFQmvT51Zsw_Za17NmBbVKK4dfgTMbIFYJU9vnHSd-PasyFLZN8H6SVzFNdSd5yjjbtUeLNa3YIBCD1V6ug9h2FO7Aw96oxMTCjh9-OCtbjFmoSlhboSGUrNYCxYVWS5Fn-xpP1fvdHAoV5stztT5MIXxAfKzw7PLw9eeayZnjKk-DLL_UJeRxr4ICxJCwS3T0j6ApoMrap0UnOHza1ye0mG8t431udH5Xi8qfQJXOQPFYxSzA36rfus5IMQikB4wJvhm3xrOlkJaJai-TjqWbAdGzafX57wdnxkfDK3qejQZN_vBEmMU1WasfB-IIDkSDu_QEq1YNEeRpQQRDRLEXV57KDAGZce3HEWq5KUf62sYL2Hepc-gGYVmoKg0w6bmRjSg55ta5MTLooNIyzBDaULxT2JHxZjEnRiuQKAhToNYnvdf7irzVdqEJ9Op09y-Ft6W1Y7B02g2bbyP0tgnDh8LosB1hCNz4sRV59K7FFyAFlSYwkCTtTX3GinJwyiltuNljFQd2rgwOQnZTL820O8_cO0puiaibiDDWHfC95OYH293JfanyBvIfSCgwYTfegeiAMD5WxfJb3v7uYMrOrYZdzay7lbzWazX-h7t9HCZZly6IEDkngD4HOJpCRMKsTeUi6g7iB2yah3sb0fmHozjMkCHJw5hUPSkVbRbHtJj36AavNgtaz7gYsbxntYbQPeN1bNlMnFK0lXKC8ALH9i3BruztCGFsGKQh_FuPu_CIh-vHEDmNJZc4H41zvylj3Or7d3ueNQa2u9aOf7pSNsg4EG24HRp5N-9MoUoIncig1tHogoNbrGu5VRJLaO5TphAsmvs4Z32cOlKW6nmi1axOTmfYTy53guvwWYpFXSiLKoKRxQ5pPXVimmlbUOn9M-6gF1_V1nmNtMK7O7asJGZDFiiSTg0pD3RVqhTKtcvlppD_AoGo2IptsYSe4bzRyJ_USD7VlmL6US61tfsrDk_HHdGUGd_mdfKL97O5dkNJ5MzTzUTQQ2TwS8GFI_EknS2SkwfDWu7Q-ZhUoXO25mSmPcjWIfaUphhypG1HAUUgP2mfIBLNn6FzInU4MCxdZ1tTjm25k-KV0sQVGxRatQ5W6bjG2H6rFiMBZCWtXZVMJQVYg4lri9W2dErgqnSpDlakUVhF6CiCyrXDyvp3HzPB7RETffRKn69AzB-9KPgkFrSoYDBkZ4kSz1D3D2DQJRJl6xiJzeVVUlj8BQFnZx63EPrDl8Mvn33NmTV8RyBvnbWPJ4daa0KSNP6m_OUjh6fQhLtwTtVYUYSqsyNfNhdmgXSPXCaUQmerGUAGS33jryzvV6kdJ7An3zVcGOu7ZP6AGfDkkeoDLdOuTLeqWcwhw9ZbLJY5ee5KVFj8viM19kW-jhYeJZHntSjetrEmCmJ131fDEc71LsKwwNLJE92nYsRIghkImpQMhTxtIXjgJ-JRaH9tpWkPcL6P6FAKoGFTWJ0uxlsnEQEg3ad-cwh6bNh_9ramKzdU1MK93ixIw1NgfLniXzsfnJWLdcPR1JtDSu8BUXn6qoWolR9qzncGZi22CQ6DK7i6i53SGSTG2FBezdmtQIPpeOrDQnP_ZVnU5z5TDXzvbF9P_b2znMR8XhP4mCA7_Tb-od5gB4a1E5QZ-lJyeVOx537c9iag72TvAU6HA9V0inUInTxkkK8gYQvrTo8PXTu8Fos7axl8N_ZDV7UGYEluuMxR4K9pnbL-mV7-c-dpM9D1Tx-eFvYwNIXhSWwYJ7GwN2vt2438jnEHHS39pNygnhHRerUt7NL6nIRdl2pDXVqPBu0MHO0H2LKC4yrET3Ps-fbv6f-ZR7ZC2bfhOVlqrjDn8IGyjVs-_1asuToQmMFuRESCYMPlI3wHOdqQGIKKmqDfQqRnQiiC4K8V1hZdMj4wLJRKIVsScOlkK0lFXW8eX6XuuRI3oVWdLj_qE72yax8_WtWxntX1N6lAF745OubzW81Mf4l2UNT5A4tystsDKyCoA3ifDvNyCEUIDn8Fe5RxHBIpRL5_vC6RD5PdyW-vY3ZITJzw-yJ0DjdUD5KwKv6yJGvlx0VfHK-RJ22ooAiQgtkwyF-X8zp7tr4LMCJOF4ighmupfEySVDszlwuKK-DZnAGV0lzcfLI4LEoeSfCbxqWTsjoC2doWj7rs0SXYJRsF4XXpq_o_1fffub0wtLdIeI8b8Z1Qv8NTKOKO1NyRjBjZan2U4hbucfxLqP3zPj9NkmiXAoP6nMZ9IWT_Rn7ycR4v7yCFUPHyGWZZJl7e_OAhDhnrozpK55Sl9z4f64xEAoBtYHUovAhaILBxxNlq9mPgV7nzRLnyxTxZUy4-gMCvN5TKGT3cQc4LHwXP4O3jkRIVmov44CZ7EkYssp9k-rrZ527TEYa_tygsCupdsbChidOhdVWCk9PSK_VTomWHlbYXoFOUiqzOpekWOws71LSuNHwFybQ4djz4xfKKU-HwXb5Jpca7y04ZCxQ__w"
					}
				]}`),
		GrantTypes: []string{
			oidc.GrantTypeClientCredentials, // Machine-to-machine
		},
		TokenEndpointAuthMethod: oidc.AuthMethodPrivateKeyJWT,
		DpopBoundAccessTokens:   true,
		// RFC 7662 section 2.1: the example resource server introspects
		// this client's tokens at the timestamp endpoint.
		AuthorizedIntrospectionClients: []string{fixtureIntrospectionClientID},
		// Pairwise sector identitier
		SubjectType:      oidc.SubjectTypePairwise,
		SectorIdentifier: fixtureSectorIdentifier,
	},
	"5stz52n91hr7aw9q1h5hbuvkt2ovevdw": {
		ClientId:   "5stz52n91hr7aw9q1h5hbuvkt2ovevdw",
		ClientType: clientv1.ClientType_CLIENT_TYPE_CONFIDENTIAL,
		ClientName: "resource-server",
		Jwks: []byte(`{"keys":[
					{
						"kid":"5stz52n91hr7aw9q1h5hbuvkt2ovevdw",
						"kty":"AKP",
						"alg":"ML-DSA-65",
						"use":"sig",
						"pub":"_KTzBDDQfLjZoaWyiya6SyqifQ8_slfhTQ9p8-BJ_ClGp_mHGrurKm9aLaztok9vm9wnfvYCR8orQobC9HZWgjJl7yM4tkxNInBOSjJjBB5ZIlpuInzR6QrFSeSTRc8qftpuPpULp1HjZyBKxkKPn8LrnFM4AB4vHabGNUjT2uMMwcIJ7iF2F4tNV9Nk9ioT1hxV6oFU8cwLBH0_gYFsENlztmlxqecEBgk9TGtCCj-tmN5oRqXpYA2wQrYCkRO3iDUqZsqxwb8oyr7cvD-RDCKKQTSkVJFKUUcDOl3peqcSEcGz0sDZXPqiiPldj_vsiVstYYY8ewOsL1yA-3DBD9BEzuWQ1i1CMLcLEL_c9PwW5t8ro_o9we4i0Io-TrvPGiLJFQOgZI1xO2JSusjjtcZ8FFzw0Oih2z7s8IgMJZ9R_qpi6SnYmQrl1LQoL_J7lcbdLXxSWcD4juNOIWLFs8VLPFcWwAu3X284Ov_ul3eZQ8HPOkFMkdJZMJOHtY3Cw87qL9otplpC4EW2_Pjmfzl9hDUMGCdDV0GEOekcjnvBg5byxQ23ZLfTLnq2mxhpo3kbyNALOnXEfKdLnC6zI580VNmVcJDF3gEsWS8fSILgHos0k5NzCD94VlkRoKw7XimMF6PE53VNomuqsuU1YYIPevohZaMDI89w84NBKHFkwoM2LhnFROD1ZmExMRdu_ZBoQmiYfkg1i8x_47mu1q2gzxwClrcsf4eTFM3QW6zOZbAojN9IojCgWkansLy1DvDcQANhxPUB--w10Vl4lLbz8kIWVNCRTweBaPv5WWBxJQFZIEuMcU92X9Gh_Wgbpebbca_bS9aihvIyW4uBhwskwtNZtL9prMdNZ8mxGrI1ufJ8KJvDQDyUczWPn4U96IV8xsMTQo10Z2uvWYucVDvJn7UZ5szaEgFPMttD1-MbIe2OMn7BCItCMNVNWCyXmLuIxGSdIx9FGhlmLJuCsWsfSABOrtEXWSRyVHV_-IAWyoZkNnqH6Q3UtaZmUzi8610vjSCsdT7O9rLo8KQH1eW_LjjNAsSjIPdE2qp4S4UZaNPuAeubppyfHAg1vpuyXj3uJj93M5UqERT2p03FGX4k2OfFqLPksEc3n4IyaQLDCWnjK3abtfmHbO4tIuRimvNkvGdkiBq_suna9d_P9csDzOS-jTYhSqlPZDep4LePFosGH8_uA5zUOgSoVCsAyayZjoqTZdeEOI_p-9NUIgYg9B0_6KZif1wx1QCRYslHy-qL7E0ykTpCIQSbn_Zj4CHnEChQINcXcfXG4KwCepgaIv1_nLiHhiBMtTCsGvm870rwFH-aP7Gc0oEeipwjdF90xD79KBZKfSFYI9Et7qPTdI9XBiSmToyrql5h3u4q_Lzq_Ywp9jVRq8jnWltYjJSU1eaIjXm6BTkS3UNZ60GJbgtp8rxdSta8VkPU7Bfo5ahAQNhuWbeuiXAlaZ-elIzf_slooOYTdS6FTfvI5AFsIs_tIMh7XISgAq8DF2uL3e4ZiT03WNPhNdm2eZT0WZwXNNZp62-XHL10vuHHD442cfpzGGojsNuuMz2yFAwr7EUZwFf_x-UgcqRTYmRoInqhm94W5EzbuKsQgDOSoI6vubyElrkL37Xwq3OPRTbog_nogoaQopojE3JeYP522vj4hw_XL6FAlktd9tV4cJHouVf19qr5azPQDWspup1omB_C0b2ZXStoopeFcYjgzbXRppjA1LPlO_t9uS2IkAMXSglPHr22Gt-FkUVAG6bEksk-96Zxe6xrwmTLPkqYbbZ9quhoy-Qk680vIx0giz7qnA2rVEAhZK5L48DCUmJC4DRqRFeE810smw_G-6ibja4EtO6jagw83HWQI_4A8Lx9q93ohXEX_QCgGTDEmvsSNbealRPHcWqGdmAWZGa0Q2rj_7XqbTatBRD9sfqWtTNFF-lrtJsSNPlkcvpLyRYZpFinRztqMTZTn8JT1ipP21tcNZLFaG-WqZw0Ewc5SCYfHGos6_bf6csjUMuJjLXvVQqVN0YQJTC7l1TYp2KqKRf1YxifatcAW-rR0Eb5RLfomAbRu5PcdcwoCVfbjyxOZpB3KoXhenON45G6wErPVn3Fl61JNSJ7KwYhq66nTxZnicXSZek7cIyrpwL8_rY9u6t0Y--YZdHDugG1ys1ZTsdQLsTqunt97WGzsqnCwSQbupXsVcYdaCpJy_Vkix1uR77Zsai21bRJhyw0BfN99ojS1iHnBmS019CiJNQFVTQ3uOWyIzOwDTpPiV6tUZL2yIoug7MtCb6sXYOrb2hNMn-_lOVngtBHy0cm7naYlgnfRGiBF6ulEngzNHl32X58S_rE57GYk3n2QMqZVQ75JWPt81LXmyADYnKvB9Wdwej-YzSe18RBgqb2qU8SIhUr5UVQBdGB5cxWaPz2aHvNnDmf0VvNezweQ2udqzmbSNrp8sSIkvg2ZgPtKv6B1NHkBV1S4iW8kfovykqnwXOZ1OWZqzWbarmeUJTzOc5Xss6P7uCSNWL8RCpBSjMWPaAJeE5s79_-_8NxbNGKLbfD3AMj9Kljx053Fr0BZPQE-4upj4wgj-u1gcZljghjyZY"
					}
				]}`),
		GrantTypes: []string{
			oidc.GrantTypeClientCredentials, // Machine-to-machine
			oidc.GrantTypeTokenExchange,
		},
		TokenEndpointAuthMethod: oidc.AuthMethodPrivateKeyJWT,
		// Pairwise sector identitier
		SubjectType:      oidc.SubjectTypePairwise,
		SectorIdentifier: fixtureSectorIdentifier,
	},
	"6779ef20e75817b79602": {
		ClientId:        "6779ef20e75817b79602",
		ClientType:      clientv1.ClientType_CLIENT_TYPE_CONFIDENTIAL,
		ApplicationType: "web",
		ClientName:      "foo-test-client",
		GrantTypes: []string{
			oidc.GrantTypeAuthorizationCode, // User interaction
			oidc.GrantTypeClientCredentials, // Machine-to-machine
			oidc.GrantTypeDeviceCode,        // Device-to-service
			oidc.GrantTypeRefreshToken,      // Act as user
			oidc.GrantTypeTokenExchange,
		},
		ResponseTypes: []string{
			"code",
		},
		ResponseModes: []string{
			oidc.ResponseModeQueryJWT,
		},
		RedirectUris: []string{
			"http://127.0.0.1:8085/oidc/as/127.0.0.1",
		},
		Contacts: []string{
			fixtureContactEmail,
		},
		// Authentication RSA public key
		Jwks: []byte(`{
					"keys": [
						{
							"kid": "6779ef20e75817b79602",
							"kty": "AKP",
							"use": "sig",
							"alg": "ML-DSA-65",
							"pub": "DZfZOTMn6n9JssfhgeDat6NcdbGztnePQHMdy8AqkCKPTfXP9EhMOm_Ti6ppKj5pKj8Q0e2-qgPIRMuYpkHTNqBT-05gQZMRRTtWenDUAERrozeuWrwgHazklp9dN3hXm1rR1n_kJQybS893ru9c7W8AS98b9avf6UwoqW4wzLz0DokZfodEhkT8xCMiQvGfUnCXB8QWVz3P7uDnxjHlhU1f3D537yUo4FyBYGU9E5taTxJlCLATBr4BH3cP9zw-UQUVyw5uO5sHPX5csBu96rLoPIRoXQeQDsRjosacx4pXnHe37NIi6gKLmM9lJxA4hBxNFjMEBO9acaVcyYlt6KWdCw5wYDs3G-e5tDcEfWmBMNdjsaJMORKx1nF_FOmHVShr8NgKb4ySS2XioRJ2oqJoEH6gW01kOAc8PWQ6LpUfWtWQL1fpV-t1zX4c2gTmSx21pY9gCuOUDGwOAs9bmqQd7NU6bzrm3iZpejlvNVpobrXAAOLpTLAVcocuH4BqrvFoFdqTugTp6Fq8GJU485dnt2YHc-uJNufhPQISBAWeofhSJ2wp6x0N4j3W1h-hK-m0c_LX9jRdngVg9zjhMQjOCQnyBSOGTYoLq8jnVJ6uDQOcr-BcUzPzSqvupkevApGH2UNjFShmn-NAtcAf0FXOZci_aYZTAIXIaQRCDANLO8xuhaUJUrOfMSz0_9kyBQUOjozNpMEnn_6eMqzXkyfrVybUOcq8h-v68r3sA5Sa2SYDPN_S2Q0-hw5T-6v2dFYMRN1JFPKfKCdq6UF-SrCCMmRkg7jkUDGwcnxR8rO45_Bc9iRyeLUaT5e3F90Jm_bz4ON0P16SjOMktqwaPXDkNqKSwUElvium-cbxNrHDps97hiM6oTlJ_5axt91NPL5RhVR_ryB6BJV_ZuYHv7ItlF-lMskGF2yMg-FHaeQyH7KO0UNtZvxN0MhWO4FV_RFlz4jA7jXIL6qdJUGhFG3g-ntCOwytAAqvt-5HDhz_BDUldZTlZij8GUx_7sNGVGCGoICXQvsHUtX52vLOP3fp6xf0yFijlsFzAXiggf11q8BtNk6ukHv-xGdoClxByQPk8y6fkU5ztgZWhY3sIRIrScaaSIHjUtcZAmLAhgPYEq5uIMi2FFuCnb0sPcrsZz0zh6tOB-35ndoH8Yz18R-GNkxNuN59mAuNmaUgKaO2iQkbDJWfbC590Pko0Hw3IOua_3PgbCwP1AMW4LgyxerUcl6zGDPoZKTbIQM5iELda7KprEZiuQ5FZzKyA4-5NjJaPPRJq1OSoLiy0iuVrAMn0UNkvz3MUUeDdYHML9lc6-H8NVOwrOMqWfo_7gAWcrdsmtMTh6gBz2w79ip9v1r9DUSrfzwt6t19HVnFJDdExM6YwQVfwQZEM-5kFRfsyVZNrH_TTtJuLtN43xCF1044efDLGBo_7YKY6HPggmHSM3CKJaGct13P_J9Rk50SvOCGt5oCt4qMM9Ybebd4S-NgA_E8dCj-MxTlsY8fG8Jz0vLXlRLfA7_rl4_1DDTzfqD4feYziixJlH_Wv7IeXsONChLNAS5k4o-SNUzzovnLc1yg7pZC8XzIyjDoiLgofAVsxq7lPDFC_tx75sfDsxbaGn7o59b4V0xRYp9hbCNLf1qcy36LCzaFZnn7jR86-WRSMq-FWJ77WD4mlaWu3Jmym62m_j0DHva5MQJ1NvMmmKt-MQF7BENMbOyvbsUhg97_lg2W6SH_0v55LaWPNL5tp8VoHKcghQB8aEEdXVhy9aaEPbZWnCq6LylF-ihDrulPAFPPmmZqaFoOU0y4QOSiQnBBWqwBv2BqsgGa5gYOZY23Sp99lcJNaqkZ8yWVXaUntn9NMzlwFEVoMydUsOH5OZLjXO3OAXJK8-EIs7lumvZaiCOVoNCtdUSpd85KToQsscLG5N-NkPOpBsZJTB3Jg9AQgmmruMgC1FDJQuhb790tTHAWxYc4d7MsoAek4jM8ovWKc6zE0BjO8kllQWozmo29f5zLxGQMk1KkwbbdSOidbNDQrFjXkakCa1IjzbNX0078NaEoe26VPVh5-EtxdiiVuvFnBGYtRpA9I0Mt0toI8Bl7kP1qhOQdERIpYqmHLkmzckaMzdGbr_uP5MO_zBBS4r4_jkj1z5e3Svqetl8L9tjxEUOd2N23GrcwGBnQ2BW1pCFJYfKSr3H4_YY3unvaAx_t9oEmpJ94dt_T2cEqg_ubmXsxrlvQTOyrBO3W-7TVpRF2zFDXunNLX3MQnIf0yUTmSdzCZ6RHs3OZ5uEus1C6RQRCinSXFZsvv7q2IxTiUstnBCuLd_WOBjcJbZCnu6EtcG3guWDSYspswjvYcYD05x7tFNCCwAIYaYFQYH3bwhBNEzQgHc3OS9JAIFSwIhJy40truIpiDx45iYYCvKvwRfkVqzcwNHFvSQ-ioGF_fkqqBD5l4HjuCdtHJSptz4tdnBKyGRj5N3tXvCB3lmPIlOOTcq3L_DuIzAybCYsy4kibv5xvH92O2j5KtftQhFantcUWwRaaQl-pkkAjXCJhDXkVYONR6Z9BrhoK_DOyCzYKk5iMPu44jp7yNjCIuEHn278wYgeFBZg"
						}
					]
				}`),
		// Pairwise sector identitier
		SubjectType:      oidc.SubjectTypePairwise,
		SectorIdentifier: fixtureSectorIdentifier,
	},
	"public-client": {
		ClientId:        "public-client",
		ClientType:      clientv1.ClientType_CLIENT_TYPE_PUBLIC,
		ApplicationType: "cli",
		ClientName:      "cli-public-client",
		GrantTypes: []string{
			oidc.GrantTypeDeviceCode,   // Device-to-service
			oidc.GrantTypeRefreshToken, // Act as user
		},
		Contacts: []string{
			fixtureContactEmail,
		},
		// Pairwise sector identitier
		SubjectType:      oidc.SubjectTypePairwise,
		SectorIdentifier: fixtureSectorIdentifier,
	},
	"attestation-client": {
		ClientId:        "attestation-client",
		ClientType:      clientv1.ClientType_CLIENT_TYPE_CREDENTIALED,
		ApplicationType: "cli",
		ClientName:      "cli-public-client",
		GrantTypes: []string{
			oidc.GrantTypeClientCredentials,
		},
		Contacts: []string{
			fixtureContactEmail,
		},
		TokenEndpointAuthMethod: oidc.AuthMethodClientAttestationJWT,
		// RFC 7662 section 2.1: the example resource server introspects
		// this client's tokens at the timestamp endpoint.
		AuthorizedIntrospectionClients: []string{fixtureIntrospectionClientID},
	},
	// draft-ietf-oauth-spiffe-client-auth-02 reference workloads of the
	// example.org trust domain. No client Jwks: signing keys come from the
	// trust domain bundle (spiffe.BundleSource), proving the decoupling.
	spiffeMyOAuthClientID: {
		ClientId:                spiffeMyOAuthClientID,
		ClientType:              clientv1.ClientType_CLIENT_TYPE_CONFIDENTIAL,
		ClientName:              "spiffe-workload",
		GrantTypes:              []string{oidc.GrantTypeClientCredentials},
		TokenEndpointAuthMethod: oidc.AuthMethodSPIFFEJWT,
		SpiffeId:                spiffeMyOAuthClientID,
	},
	spiffeX509WorkloadID: {
		ClientId:                spiffeX509WorkloadID,
		ClientType:              clientv1.ClientType_CLIENT_TYPE_CONFIDENTIAL,
		ClientName:              "spiffe-x509-workload",
		GrantTypes:              []string{oidc.GrantTypeClientCredentials},
		TokenEndpointAuthMethod: oidc.AuthMethodSPIFFEX509,
		SpiffeId:                spiffeX509WorkloadID,
	},
	spiffeWITWorkloadID: {
		ClientId:                spiffeWITWorkloadID,
		ClientType:              clientv1.ClientType_CLIENT_TYPE_CONFIDENTIAL,
		ClientName:              "spiffe-wit-workload",
		GrantTypes:              []string{oidc.GrantTypeClientCredentials},
		TokenEndpointAuthMethod: oidc.AuthMethodSPIFFEWIT,
		SpiffeId:                spiffeWITWorkloadID,
	},
	"urn:solid:attestation-server": {
		ClientId:   "urn:solid:attestation-server",
		ClientType: clientv1.ClientType_CLIENT_TYPE_PUBLIC,
		ClientName: "Remote Attestation Server",
		Jwks: []byte(`{
					"keys": [
					  {
						"kty": "AKP",
						"alg": "ML-DSA-65",
						"pub": "0lwENmDIahyYU07RgZVga2jsieLrR7F8_SXzaHnhuehsn7qjSBmiGkbGB_n1dnAcKcwrQYnGr3ahwvb4Vgk9pV936pNNWMxjcNyERk41iLJbdS9AYxyvApBGFs0BU3mhIXOQHFf0EK5NCroaUhAT2wMcdYQOl8mtXUHLpPGpAGFyMrOmc1RInZDfNqd-ymLjydiYW83ZHdGfamhNeCnSGFnRo-pv-yXs3pALkc72VWi7FwvdnukakLSN_LQBXz3WI5_JZjZZAVZXk7K-Gud35se55ghB-WVFsmooPV7x0vA6Fcrlpy3pFjBjDjupEPwU7LHm-k4hZ5UVvfkXBPjBgmJdnyEwk8biqp5kDOB8pMqiNBj2v9hKly1JLcnliesKIaAjkclkA_fc3fmlPaQNwDu110JZJqje2N7hmRQvf_tFhp66cssBKkmFk6JLdvH3_oNEeopW83NoMJ1xhEE-uClMXhozs3HFRhjklgdpag_ucR55o9B53IAuDVKCwWjgSN78ux7WD7G0zDx2Z6fNSoBYgcP_E5JZDg8LSGAbbq5AEomIm6zwyj4o7FZKeJywRMzOpZSwYgo5cL6N4EiP89rsjVRc5o58uoJFKAEx9y9hMJCRzR3V-i8gI8X4xS29Vu3hi0xJ65VEh2oOuJVBZJumUtLoK7XuJBU91hjcoPC9S9D36I7pqiL6pjzWkJyDt9arO1M8KHpF-NRm3qDXiDXBeN18HvOdf-_Vp9NX9bjeKs1ZT7h862R4qaV1fAe-gMJuxU7SO6tEeffQFkcfJ5K5Y2kVBJXRIe5M5MbMdIGjxQ1V9tqzrEahySuIJHNV4NySmByg84lAyH5zi_Ekv8MBOTbHyXoxK-H2RpGr9aOdSdnwso5oX8dD_ipGkkvdnqAniRpsI1XEOU6mdFbqw7CZyyFOHLHLkIYKkC_ciXzTUlbDFhUw7IGW77ylTCCaWYO7MqbBPAHrJ0LdA1zS-Z61FOx7SX3NDgodEgdM_A664HgMXwgiCGKa5oAU_675GFBLZ4axhjnpWgXi2odjuS06jhzY1PSUDwhlUG9yCQcYPUBCYOSdfumD9WpZEcsr6UhHP80hIG76RURdlViXXJ1-RTOXGw39Hc4HyoLIaWBAKywsLdTq2sqlZvJi8cAkLDrYafz6rRWhFcxhsvcrLaF9N2XuFYGeAxFrw8SstK7bYgUDZRZ-AzfYgWBuHXkRTAB_lslwHNXHGQhHCjLIstDCIrxRPwqiUpfl9b7tyzzv0_aQw_r-AAanAq6tV3vyryYkfskJwRt3iOhpcIgD2KACcPkiEKHwZXXldnCkw0EdlWkf4LFpKGhIuAIkukaJvb4gNit7A2SdXe_CZoiDZCs1ds5T0nxlIUy-rjR6d6VTSRCxiA04eZbKbHV_V-7uUnkXldaxABIAdWQSSyOurXe-OUJrooMUeFnIj4FZvNpIfbs6-EAvuDjCvf8bBHXCcS4LRklRyQNFmvaf2JAa9E_agjp8XY9di6qqj2_b8PWGGZzV88ois5V_64H6U63M3QpKxm_YblF6UBx4uVJsqidTn8arONQWiUvPr8uFS3qRm2u9PPDjcn__Z-HnO4xPBBoUFnWBdkSwgGhWMjUGlF4Azj4R_LAl1KXMSQ-kL4Hmg8Kw8FETlx8ee6hlHENPwkrLRY8DoWRymW2A_beEvrEmthutHt7WpSqc70AerrLI0Q22aS2cw-EwcQldAs3FnqeHnBgWWfu0MqUu628tfrOYFjQ5vlUFvKmQQomg5sSMM__foFM4eCnWtUrEbcmsMPa4eJr36sKDAe0RlufE3LYN-TOHPq62xGOYw0kRfTw94OzGa0iita1m4xckEcuLXetPRZDeGD0zLCA0T5FKtfV3zgzpBj1rJZyvaZq-bO_yAYe1jr1q6O92V9B43vBpFeJptLdjsBI7vrOf4pKp_YftQ4SisLPKfrK8xOjb3xZ_E42SLjm5znkCq5gmnPd8s_RUA4HBz5yHo2Cgz0UEAxlKqJc_ZM-AFxRdRz29BMns6wNcUMWydC0ClIIHmR5qv54pJSOraJwIcuqZzsKxqm1uXav23WQdOUA8qYFkIHTIl-SyNncsYjiyjpM2uY1DkiJtEPnRaBdBKMzKwO9q_9jCCXKyERrba4FYQGPWOg9p5CWWFx0dlZQ2N8mrRSRCqJcFOhp-xCqho9drRpHd_htD2dbMoQDEq0xCxx8rUmtqW9FJluc3oGWsb93y3vrvuAh1IrhQ_Uqi4Js-LB8mfzxAxF5WU72znYnlYLuRM7TE4DEtxeqSzROI8Junysblsaw8_ail6edp7TmZ9j4qTG0V0p-y2tGuIFtzczBrYZDLYtmvDfhhSju1vzIG2XJW2VXwn9Dt8jZSA7x3r6H2LYFR72Hp_9wsqy7UzJ7mF-3kQFIvwBgq28zTDgipMHCwirGEfHIYc3Ifb29U-kOyIZParO-tOxbxzav6Yg25_fSXmTNzYqaDKpiz7E3r_2GtIJPZ1XEJ0aTMAULhc0CCnmBaCGBRxPtmhZp-NWsShySl2FksZ1XF33t6Xk8Jspx4bhP8FzTB8PhVpEsJl_SzphV_WE21ke-_iIQUIflLShk"
					  }
					]
				  }`),
	},
}

// -----------------------------------------------------------------------------

func (s *clientStorage) Get(ctx context.Context, id string) (*clientv1.Client, error) {
	// Check is client exists
	client, ok := s.backend[id]
	if !ok {
		return nil, storage.ErrNotFound
	}

	// No error
	return client, nil
}

func (s *clientStorage) GetByName(ctx context.Context, name string) (*clientv1.Client, error) {
	// Iterate over bakend map
	for _, c := range s.backend {
		if strings.EqualFold(c.ClientName, name) {
			return c, nil
		}
	}

	// Not found
	return nil, storage.ErrNotFound
}

// -----------------------------------------------------------------------------

func (s *clientStorage) Register(ctx context.Context, c *clientv1.Client) (string, error) {
	// Assign client id
	c.ClientId = random.String(16)

	// Assign to storage
	s.backend[c.ClientId] = c

	// No error
	return c.ClientId, nil
}
