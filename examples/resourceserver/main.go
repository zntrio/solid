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
	"crypto/ed25519"
	cryptoRand "crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"time"

	discoveryv1 "zntr.io/solid/api/oidc/discovery/v1"
	"zntr.io/solid/client"
	"zntr.io/solid/sdk/types"
)

func ResourceMetadata(issuer string) http.Handler {
	// Prepare metadata
	md := &discoveryv1.ProtectedResourceMetadata{
		Resource: "http://127.0.0.1:8085",
		ScopesProvided: []string{
			"timestamp:read",
		},
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Set response type
		w.Header().Set("Content-Type", "application/json; charset=utf-8")

		// Prepare response
		if err := json.NewEncoder(w).Encode(md); err != nil {
			http.Error(w, "Unable to serialize response", http.StatusInternalServerError)
			return
		}
	})
}

func ResourceHandler(issuer string, pub ed25519.PublicKey, priv ed25519.PrivateKey) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Create the timestamp
		now := time.Now().UTC().UnixNano()

		// Create a random nonce
		var nonce [8]byte
		if _, err := io.ReadFull(cryptoRand.Reader, nonce[:]); err != nil {
			http.Error(w, "Unable to generate nonce for signature", http.StatusInternalServerError)
			return
		}

		// Encode timestamp as a byte array
		tsRaw := make([]byte, 8)
		binary.BigEndian.PutUint64(tsRaw, uint64(now))

		// Prepare protected payload
		protected := []byte("signed-timestamp-protocol-v1")
		protected = append(protected, issuer...)
		protected = append(protected, nonce[:]...)
		protected = append(protected, tsRaw...)

		// Set response type
		w.Header().Set("Content-Type", "application/json; charset=utf-8")

		// Prepare response
		if err := json.NewEncoder(w).Encode(map[string]any{
			"@context":  "https://zntr.io/schemas/security/v1",
			"@type":     "SignedTimestamp",
			"issuer":    issuer,
			"timestamp": now,
			"signature": map[string]any{
				"scheme": "ed25519",
				"nonce":  base64.RawURLEncoding.EncodeToString(nonce[:]),
				"proof":  base64.RawURLEncoding.EncodeToString(ed25519.Sign(priv, protected)),
				"pub":    base64.RawURLEncoding.EncodeToString(pub),
			},
		}); err != nil {
			http.Error(w, "Unable to serialize response", http.StatusInternalServerError)
			return
		}
	})
}

func main() {
	ctx := context.Background()
	issuer := "http://localhost:8085"

	// Create OIDC client instance
	oidcClient, err := client.HTTP(ctx, "http://127.0.0.1:8080", &client.Options{
		ClientID: "5stz52n91hr7aw9q1h5hbuvkt2ovevdw",
		JWK:      []byte(`{"alg":"ML-DSA-65","d":"c29saWQtcmVzY2wtc2VlZC0wMDAwMDAwMDAwMDAwMjI","kid":"5stz52n91hr7aw9q1h5hbuvkt2ovevdw","kty":"AKP","pub":"_KTzBDDQfLjZoaWyiya6SyqifQ8_slfhTQ9p8-BJ_ClGp_mHGrurKm9aLaztok9vm9wnfvYCR8orQobC9HZWgjJl7yM4tkxNInBOSjJjBB5ZIlpuInzR6QrFSeSTRc8qftpuPpULp1HjZyBKxkKPn8LrnFM4AB4vHabGNUjT2uMMwcIJ7iF2F4tNV9Nk9ioT1hxV6oFU8cwLBH0_gYFsENlztmlxqecEBgk9TGtCCj-tmN5oRqXpYA2wQrYCkRO3iDUqZsqxwb8oyr7cvD-RDCKKQTSkVJFKUUcDOl3peqcSEcGz0sDZXPqiiPldj_vsiVstYYY8ewOsL1yA-3DBD9BEzuWQ1i1CMLcLEL_c9PwW5t8ro_o9we4i0Io-TrvPGiLJFQOgZI1xO2JSusjjtcZ8FFzw0Oih2z7s8IgMJZ9R_qpi6SnYmQrl1LQoL_J7lcbdLXxSWcD4juNOIWLFs8VLPFcWwAu3X284Ov_ul3eZQ8HPOkFMkdJZMJOHtY3Cw87qL9otplpC4EW2_Pjmfzl9hDUMGCdDV0GEOekcjnvBg5byxQ23ZLfTLnq2mxhpo3kbyNALOnXEfKdLnC6zI580VNmVcJDF3gEsWS8fSILgHos0k5NzCD94VlkRoKw7XimMF6PE53VNomuqsuU1YYIPevohZaMDI89w84NBKHFkwoM2LhnFROD1ZmExMRdu_ZBoQmiYfkg1i8x_47mu1q2gzxwClrcsf4eTFM3QW6zOZbAojN9IojCgWkansLy1DvDcQANhxPUB--w10Vl4lLbz8kIWVNCRTweBaPv5WWBxJQFZIEuMcU92X9Gh_Wgbpebbca_bS9aihvIyW4uBhwskwtNZtL9prMdNZ8mxGrI1ufJ8KJvDQDyUczWPn4U96IV8xsMTQo10Z2uvWYucVDvJn7UZ5szaEgFPMttD1-MbIe2OMn7BCItCMNVNWCyXmLuIxGSdIx9FGhlmLJuCsWsfSABOrtEXWSRyVHV_-IAWyoZkNnqH6Q3UtaZmUzi8610vjSCsdT7O9rLo8KQH1eW_LjjNAsSjIPdE2qp4S4UZaNPuAeubppyfHAg1vpuyXj3uJj93M5UqERT2p03FGX4k2OfFqLPksEc3n4IyaQLDCWnjK3abtfmHbO4tIuRimvNkvGdkiBq_suna9d_P9csDzOS-jTYhSqlPZDep4LePFosGH8_uA5zUOgSoVCsAyayZjoqTZdeEOI_p-9NUIgYg9B0_6KZif1wx1QCRYslHy-qL7E0ykTpCIQSbn_Zj4CHnEChQINcXcfXG4KwCepgaIv1_nLiHhiBMtTCsGvm870rwFH-aP7Gc0oEeipwjdF90xD79KBZKfSFYI9Et7qPTdI9XBiSmToyrql5h3u4q_Lzq_Ywp9jVRq8jnWltYjJSU1eaIjXm6BTkS3UNZ60GJbgtp8rxdSta8VkPU7Bfo5ahAQNhuWbeuiXAlaZ-elIzf_slooOYTdS6FTfvI5AFsIs_tIMh7XISgAq8DF2uL3e4ZiT03WNPhNdm2eZT0WZwXNNZp62-XHL10vuHHD442cfpzGGojsNuuMz2yFAwr7EUZwFf_x-UgcqRTYmRoInqhm94W5EzbuKsQgDOSoI6vubyElrkL37Xwq3OPRTbog_nogoaQopojE3JeYP522vj4hw_XL6FAlktd9tV4cJHouVf19qr5azPQDWspup1omB_C0b2ZXStoopeFcYjgzbXRppjA1LPlO_t9uS2IkAMXSglPHr22Gt-FkUVAG6bEksk-96Zxe6xrwmTLPkqYbbZ9quhoy-Qk680vIx0giz7qnA2rVEAhZK5L48DCUmJC4DRqRFeE810smw_G-6ibja4EtO6jagw83HWQI_4A8Lx9q93ohXEX_QCgGTDEmvsSNbealRPHcWqGdmAWZGa0Q2rj_7XqbTatBRD9sfqWtTNFF-lrtJsSNPlkcvpLyRYZpFinRztqMTZTn8JT1ipP21tcNZLFaG-WqZw0Ewc5SCYfHGos6_bf6csjUMuJjLXvVQqVN0YQJTC7l1TYp2KqKRf1YxifatcAW-rR0Eb5RLfomAbRu5PcdcwoCVfbjyxOZpB3KoXhenON45G6wErPVn3Fl61JNSJ7KwYhq66nTxZnicXSZek7cIyrpwL8_rY9u6t0Y--YZdHDugG1ys1ZTsdQLsTqunt97WGzsqnCwSQbupXsVcYdaCpJy_Vkix1uR77Zsai21bRJhyw0BfN99ojS1iHnBmS019CiJNQFVTQ3uOWyIzOwDTpPiV6tUZL2yIoug7MtCb6sXYOrb2hNMn-_lOVngtBHy0cm7naYlgnfRGiBF6ulEngzNHl32X58S_rE57GYk3n2QMqZVQ75JWPt81LXmyADYnKvB9Wdwej-YzSe18RBgqb2qU8SIhUr5UVQBdGB5cxWaPz2aHvNnDmf0VvNezweQ2udqzmbSNrp8sSIkvg2ZgPtKv6B1NHkBV1S4iW8kfovykqnwXOZ1OWZqzWbarmeUJTzOc5Xss6P7uCSNWL8RCpBSjMWPaAJeE5s79_-_8NxbNGKLbfD3AMj9Kljx053Fr0BZPQE-4upj4wgj-u1gcZljghjyZY","use":"sig"}`),
		Scopes:   []string{"openid"},
	})
	if err != nil {
		panic(err)
	}

	// Create the signing key from a cryptographically secure source; a
	// deterministic seed would let anyone reproduce this resource server's
	// key material.
	pub, priv, err := ed25519.GenerateKey(cryptoRand.Reader)
	if err != nil {
		panic(err)
	}

	// Create router
	http.Handle("/", Authorizer(ResourceHandler(issuer, pub, priv), "timestamp:read", oidcClient, types.StringArray{"urn:solid:loa:1fa:any"}, 30))
	http.Handle("/.well-known/oauth-protected-resource", ResourceMetadata(issuer))

	log.Fatal(http.ListenAndServe(":8085", nil))
}
