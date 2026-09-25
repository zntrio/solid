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

package verifiable

import (
	cryptorand "crypto/rand"
	"errors"
	"fmt"
	"io"
	mathrand "math/rand/v2"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// uuidv4From returns a deterministic UUIDv4 read from the given io.Reader.
func uuidv4From(r io.Reader) ([16]byte, error) {
	var u [16]byte
	if _, err := io.ReadFull(r, u[:]); err != nil {
		return u, fmt.Errorf("unable to read random bytes: %w", err)
	}
	u[6] = (u[6] & 0x0f) | 0x40 // version 4
	u[8] = (u[8] & 0x3f) | 0x80 // variant 10
	return u, nil
}

// validUUIDv4 checks RFC 9562 version and variant bits.
func validUUIDv4(u []byte) bool {
	return len(u) == 16 && u[6]>>4 == 4 && u[8]>>6 == 2
}

//nolint:paralleltest // Stateful tests
func Test_UUID_Generate(t *testing.T) {
	// Create a deterministic generator
	g := &uuidGenerator{
		randReader: mathrand.NewChaCha8([32]byte{1}),
		secretKey:  []byte("my-very-secret-key-for-mac"),
		source: func() ([16]byte, error) {
			u, err := uuidv4From(mathrand.NewChaCha8([32]byte{2}))
			if err != nil {
				return [16]byte{}, fmt.Errorf("unable to generate a random UUIDv4: %w", err)
			}
			return u, nil
		},
	}

	t.Run("first generation", func(t *testing.T) {
		expectedOut := "0CNFiOj2HZ6UJWLjN7gbh1_G7ZccsC1UmciKcFI0c9whIjqRLKso9eudH4f4ebO6pXYYxra0Ty1qSiu7lp"
		out, err := g.Generate()
		require.NoError(t, err)
		require.Equal(t, expectedOut, out)
	})

	t.Run("second generation", func(t *testing.T) {
		expectedOut := "0CNFiOj2HZ6UJWLjN7gbh1_12QMIsSQOU3HlFoFCjUlilUnODrsHJnrhhEIaSp502MZ1BkExH2DWjFcuSVP"
		out, err := g.Generate()
		require.NoError(t, err)
		require.Equal(t, expectedOut, out)
	})

	t.Run("first generation with prefix", func(t *testing.T) {
		expectedOut := "at_0CNFiOj2HZ6UJWLjN7gbh1_k0bvONQPfHurpW5fkyXs04PoOZtI7qxpcnV4gw4Ziq4Uw7mzhS4tJEgxTpp"
		out, err := g.Generate(WithTokenPrefix("at"))
		require.NoError(t, err)
		require.Equal(t, expectedOut, out)
	})

	t.Run("second generation with prefix", func(t *testing.T) {
		expectedOut := "et_0CNFiOj2HZ6UJWLjN7gbh1_1mvAnYcptJ8odhzxFNJGMkrTH1fnFhoBsWFzsp4KU3fhkKfNEfitY1X8Ao9i"
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
			u, err := uuidv4From(mathrand.NewChaCha8([32]byte{2}))
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
		randReader: cryptorand.Reader,
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
		randReader: mathrand.NewChaCha8([32]byte{1}),
		secretKey:  []byte("my-very-secret-key-for-mac"),
		source: func() ([16]byte, error) {
			u, err := uuidv4From(mathrand.NewChaCha8([32]byte{2}))
			if err != nil {
				return [16]byte{}, fmt.Errorf("unable to generate a random UUIDv4: %w", err)
			}
			return u, nil
		},
	}

	t.Run("valid", func(t *testing.T) {
		t.Parallel()

		tkn := "0CNFiOj2HZ6UJWLjN7gbh1_G7ZccsC1UmciKcFI0c9whIjqRLKso9eudH4f4ebO6pXYYxra0Ty1qSiu7lp"
		if err := g.Verify(tkn); err != nil {
			t.Fatal(err)
		}

		id, err := g.Extract(tkn)
		require.NoError(t, err)
		require.Equal(t, []byte{0x14, 0x90, 0x6, 0x6b, 0x77, 0x89, 0x45, 0xb0, 0xbb, 0x49, 0x25, 0xe3, 0xdb, 0x15, 0x1c, 0x5b}, id)
		require.True(t, validUUIDv4(id), "extracted value must be a valid UUIDv4")
		require.NoError(t, err)
	})

	t.Run("valid with prefix", func(t *testing.T) {
		t.Parallel()

		tkn := "at_0CNFiOj2HZ6UJWLjN7gbh1_k0bvONQPfHurpW5fkyXs04PoOZtI7qxpcnV4gw4Ziq4Uw7mzhS4tJEgxTpp"
		if err := g.Verify(tkn); err != nil {
			t.Fatal(err)
		}

		id, err := g.Extract(tkn)
		require.NoError(t, err)
		require.Equal(t, []byte{0x14, 0x90, 0x6, 0x6b, 0x77, 0x89, 0x45, 0xb0, 0xbb, 0x49, 0x25, 0xe3, 0xdb, 0x15, 0x1c, 0x5b}, id)
		require.True(t, validUUIDv4(id), "extracted value must be a valid UUIDv4")
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

	for range 10000 {
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

	for range 10000 {
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
	u, _ := uuidv4()
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
	tkn := "et_0CNFiOj2HZ6UJWLjN7gbh1_1mvAnYcptJ8odhzxFNJGMkrTH1fnFhoBsWFzsp4KU3fhkKfNEfitY1X8Ao9i"

	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		require.NoError(b, g.Verify(tkn))
	}
}
