package main

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"time"

	"zntr.io/solid/client"
)

func main() {
	ctx := context.Background()

	// Create OIDC client instance
	oidcClient, err := client.HTTP(ctx, "http://localhost:8080", &client.Options{
		ClientID: "t8p9duw4n2klximkv3kagaud796ul67g",
		JWK:      []byte(`{"kty":"EC","crv":"P-384","alg":"ES384","x":"yqLwlyN2qohjRcI_evlAXge2bvQWQQwGjsQNXEtfFMN613Wu6a5qfzu74vBkKJau","y":"aCVWx2cX2f7foQ0KtPGJ-TKjFMtcEWv1VQKJUL93B7ANbnwnj_Ox2DsYd64wUH8o","d":"YhOeT7joXg9LTYIFcNNAXpSfRM3GxoxfdYII4BAIJoAL1UQrHTQom0IUGxY_CLog"}`),
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

	// Retrieve an access token
	t, err := oidcClient.ClientCredentials(ctx, assertion)
	if err != nil {
		panic(err)
	}

	// Let some time to persistence to sync.
	time.Sleep(1000 * time.Millisecond)

	// Call the timestamp service
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://localhost:8085", nil)
	if err != nil {
		panic(err)
	}

	// Set the access token value.
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", t.AccessToken))

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
