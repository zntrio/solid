package authorization

import (
	"context"
	"testing"
)

func Test_codeGenerator_Generate(t *testing.T) {
	c := Default()
	got, err := c.Generate(context.Background())
	if err != nil {
		t.Fatalf("unexpected error occurs, got %v", err)
	}
	if len(got) != DefaultAuthorizationCodeLen {
		t.Errorf("generated value has not the required length (%d)", DefaultAuthorizationCodeLen)
	}
}
