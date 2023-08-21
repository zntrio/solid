package verifiable

import (
	"crypto/rand"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/gofrs/uuid"
	"github.com/stretchr/testify/require"
	"zntr.io/solid/sdk/randomness"
)

//nolint:paralleltest // Stateful tests
func Test_UUID_Generate(t *testing.T) {
	// Create a deterministic generator
	g := &uuidGenerator{
		randReader: randomness.NewReader(1),
		secretKey:  []byte("my-very-secret-key-for-mac"),
		source: func() ([16]byte, error) {
			g := uuid.NewGenWithOptions(uuid.WithRandomReader(randomness.NewReader(2)))
			u, err := g.NewV4()
			if err != nil {
				return [16]byte{}, fmt.Errorf("unable to generate a random UUIDv4: %w", err)
			}
			return u, nil
		},
	}

	t.Run("first generation", func(t *testing.T) {
		expectedOut := "1rEhxXi9mBwmkGpXxD4Njd_wHOKGDkYTeOIHSFg1vyoEtsoN7gxbzr5iA2qYWLZLSuJroVFELjREpWft1t"
		out, err := g.Generate()
		require.NoError(t, err)
		require.Equal(t, expectedOut, out)
	})

	t.Run("second generation", func(t *testing.T) {
		expectedOut := "1rEhxXi9mBwmkGpXxD4Njd_YQbaiGsOHwcZlL6rxbiIEAnEMFSY1Wv0WEuz47xjuf7I6N70gUZqjc4hpoU"
		out, err := g.Generate()
		require.NoError(t, err)
		require.Equal(t, expectedOut, out)
	})

	t.Run("first generation with prefix", func(t *testing.T) {
		expectedOut := "at_1rEhxXi9mBwmkGpXxD4Njd_MLdlJaU0J9toBacx8jjPrecLJcS2L4x1L0ejj6yoXMBuSW4pIWyA3UQ4bVt"
		out, err := g.Generate(WithTokenPrefix("at"))
		require.NoError(t, err)
		require.Equal(t, expectedOut, out)
	})

	t.Run("second generation with prefix", func(t *testing.T) {
		expectedOut := "et_1rEhxXi9mBwmkGpXxD4Njd_F1TuPP5aLrr1OShiZat5zeie1agvYviNETF61NFC3kolYRaRvKYmd9DgpRj"
		out, err := g.Generate(WithTokenPrefix("et"))
		require.NoError(t, err)
		require.Equal(t, expectedOut, out)
	})

	t.Run("third generation with bad prefix", func(t *testing.T) {
		out, err := g.Generate(WithTokenPrefix("et _"))
		require.Error(t, err)
		require.Equal(t, "", out)
	})

	t.Run("fourth generation with bad prefix", func(t *testing.T) {
		out, err := g.Generate(WithTokenPrefix("😀_"))
		require.Error(t, err)
		require.Equal(t, "", out)
	})
}

func Test_UUIDGenerate_RandError(t *testing.T) {
	t.Parallel()

	g := &uuidGenerator{
		randReader: strings.NewReader(""),
		secretKey:  []byte("my-very-secret-key-for-mac"),
		source: func() ([16]byte, error) {
			u, err := uuid.NewGenWithOptions(uuid.WithRandomReader(randomness.NewReader(2))).NewV4()
			if err != nil {
				return [16]byte{}, fmt.Errorf("unable to generate a random UUIDv4: %w", err)
			}
			return u, nil
		},
	}

	_, err := g.Generate()
	if err == nil {
		t.Fatal("an error should be raised")
	}
}

func Test_UUIDGenerate_SourceError(t *testing.T) {
	t.Parallel()

	g := &uuidGenerator{
		randReader: rand.Reader,
		secretKey:  []byte("my-very-secret-key-for-mac"),
		source: func() ([16]byte, error) {
			return [16]byte{}, errors.New("error")
		},
	}

	_, err := g.Generate()
	if err == nil {
		t.Fatal("an error should be raised")
	}
}

func Test_UUID_Verify(t *testing.T) {
	// Create a deterministic generator
	g := &uuidGenerator{
		randReader: randomness.NewReader(1),
		secretKey:  []byte("my-very-secret-key-for-mac"),
		source: func() ([16]byte, error) {
			u, err := uuid.NewGenWithOptions(uuid.WithRandomReader(randomness.NewReader(2))).NewV4()
			if err != nil {
				return [16]byte{}, fmt.Errorf("unable to generate a random UUIDv4: %w", err)
			}
			return u, nil
		},
	}

	t.Run("valid", func(t *testing.T) {
		t.Parallel()

		tkn := "1rEhxXi9mBwmkGpXxD4Njd_wHOKGDkYTeOIHSFg1vyoEtsoN7gxbzr5iA2qYWLZLSuJroVFELjREpWft1t"
		if err := g.Verify(tkn); err != nil {
			t.Fatal(err)
		}

		id, err := g.Extract(tkn)
		require.NoError(t, err)
		require.Equal(t, []byte{0x2f, 0x82, 0x82, 0xcb, 0xe2, 0xf9, 0x49, 0x6f, 0xb1, 0x44, 0xc0, 0xaa, 0x4c, 0xed, 0x56, 0xdb}, id)
		_, err = uuid.FromBytes(id)
		require.NoError(t, err)
	})

	t.Run("valid with prefix", func(t *testing.T) {
		t.Parallel()

		tkn := "at_1rEhxXi9mBwmkGpXxD4Njd_MLdlJaU0J9toBacx8jjPrecLJcS2L4x1L0ejj6yoXMBuSW4pIWyA3UQ4bVt"
		if err := g.Verify(tkn); err != nil {
			t.Fatal(err)
		}

		id, err := g.Extract(tkn)
		require.NoError(t, err)
		require.Equal(t, []byte{0x2f, 0x82, 0x82, 0xcb, 0xe2, 0xf9, 0x49, 0x6f, 0xb1, 0x44, 0xc0, 0xaa, 0x4c, 0xed, 0x56, 0xdb}, id)
		_, err = uuid.FromBytes(id)
		require.NoError(t, err)
	})

	t.Run("valid with invalid prefix", func(t *testing.T) {
		t.Parallel()

		tkn := "et__1rEhxXi9mBwmkGpXxD4Njd_F1TuPP5aLrr1OShjyGUkq9YeMXZrZjpnNAkfLorbsinjMDHdtItdsWstkmh"
		if err := g.Verify(tkn); err == nil {
			t.Fatal("an error should be raised")
		}
	})

	t.Run("too short", func(t *testing.T) {
		t.Parallel()

		tkn := "CDLDuzAwMDAtZ"
		if err := g.Verify(tkn); err == nil {
			t.Fatal("an error should be raised")
		}
	})

	t.Run("invalid uuid base62", func(t *testing.T) {
		t.Parallel()

		tkn := "1rEhxXi9m-wmkGpXxD4Njd_wHOKGDkYTeOIHSFgS9ul7cDrVX3ERymo5SfvLQH7HcuSNdpPTy2fAZKEynG"
		if err := g.Verify(tkn); err == nil {
			t.Fatal("an error should be raised")
		}
	})

	t.Run("invalid signature base62", func(t *testing.T) {
		t.Parallel()

		tkn := "1rEhxXi9mBwmkGpXxD4Njd_wHOKGDkYTeOIHSFgS9ul7cDrV-3ERymo5SfvLQH7HcuSNdpPTy2fAZKEynG"
		if err := g.Verify(tkn); err == nil {
			t.Fatal("an error should be raised")
		}
	})

	t.Run("invalid signature", func(t *testing.T) {
		t.Parallel()

		tkn := "1rEhxXi9mBwmkGpXxD4Njd_wHOKGDkYTeOIHSFgS9ul7cDrVX3ERymo5SfvLQH8KcuSNdpPTy2fAZKEynG"
		if err := g.Verify(tkn); err == nil {
			t.Fatal("an error should be raised")
		}
	})

	t.Run("tampered prefix", func(t *testing.T) {
		t.Parallel()

		tkn := "bad_1rEhxXi9mBwmkGpXxD4Njd_MLdlJaU0J9toBacxSJT3BQFDqhqt1XDKGc3Wo60WGYDKYG3jBkLtD7RK6TT"
		if err := g.Verify(tkn); err == nil {
			t.Fatal("an error should be raised")
		}
	})
}

func Test_UUID_GenerateAndVerify_WithUUIDv4(t *testing.T) {
	t.Parallel()

	g := UUIDGenerator(UUIDv4Source(), []byte("very-secret-mac-key"))
	v := UUIDVerifier([]byte("very-secret-mac-key"))

	for i := 0; i < 10000; i++ {
		out, err := g.Generate()
		if err != nil {
			t.Fatal(err)
		}
		if err := v.Verify(out); err != nil {
			t.Log(out)
			t.Fatal(err)
		}
	}
}

func Test_UUID_GenerateAndVerify_WithUUIDv7(t *testing.T) {
	t.Parallel()

	g := UUIDGenerator(UUIDv7Source(), []byte("very-secret-mac-key"))
	v := UUIDVerifier([]byte("very-secret-mac-key"))

	for i := 0; i < 10000; i++ {
		out, err := g.Generate()
		if err != nil {
			t.Fatal(err)
		}
		if err := v.Verify(out); err != nil {
			t.Log(out)
			t.Fatal(err)
		}
	}
}

func BenchmarkVerifiableUUIDGenerator(b *testing.B) {
	u := uuid.Must(uuid.NewV4())
	g := UUIDGenerator(StaticUUIDSource(u), []byte("very-secret-mac-key"))

	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		out, err := g.Generate()
		require.NoError(b, err)
		b.SetBytes(int64(len(out)))
	}
}

func BenchmarkVerifiableUUIDVerifier(b *testing.B) {
	g := UUIDVerifier([]byte("my-very-secret-key-for-mac"))
	tkn := "et_1rEhxXi9mBwmkGpXxD4Njd_F1TuPP5aLrr1OShjyGUkq9YeMXZrZjpnNAkfLorbsinjMDHdtItdsWstkmh"

	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		require.NoError(b, g.Verify(tkn))
	}
}