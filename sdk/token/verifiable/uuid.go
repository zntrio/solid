package verifiable

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strings"

	"github.com/gofrs/uuid"
	"golang.org/x/crypto/hkdf"
)

var wrappedUUIDFormat = regexp.MustCompile("^[a-zA-Z0-9]{22}_[a-zA-Z0-9]{59,60}$")

// UUIDGeneratorFunc represents the contract used to feed the wrapper with a
// pre-generated UUID. This is used to pass the UUID byte array coming from your
// favorite generator.
type UUIDGeneratorFunc func() ([16]byte, error)

// StaticUUIDSource is used to set a static UUID byte array content.
func StaticUUIDSource(in [16]byte) UUIDGeneratorFunc {
	return func() ([16]byte, error) {
		return in, nil
	}
}

// UUIDv4Source generates an UUIDv4 based byte array.
func UUIDv4Source() UUIDGeneratorFunc {
	return func() ([16]byte, error) {
		// Generate UUIDv4
		u, err := uuid.NewV4()
		if err != nil {
			return [16]byte{}, fmt.Errorf("unable to generate a random UUIDv4: %w", err)
		}
		return u, nil
	}
}

// UUIDv7Source generates an UUIDv7 based byte array.
func UUIDv7Source() UUIDGeneratorFunc {
	return func() ([16]byte, error) {
		// Generate UUIDv7
		u, err := uuid.NewV7()
		if err != nil {
			return [16]byte{}, fmt.Errorf("unable to generate a random UUIDv7: %w", err)
		}
		return u, nil
	}
}

// -----------------------------------------------------------------------------

// VerifiableUUIDExtractor extends the Verifier to add content extraction helper.
type VerifiableUUIDExtractor interface {
	Verifier
	Extractor[[]byte]
}

// UUIDGenerator wraps the returned UUID byte array from the given source to
// provide additional integrity protection to the content.
//
// The secret key is used to derive a unique secret used to seal the UUID value.
func UUIDGenerator(source UUIDGeneratorFunc, secretKey []byte) Generator {
	return &uuidGenerator{
		randReader: rand.Reader,
		source:     source,
		secretKey:  secretKey,
	}
}

// UUIDVerifier verifies a wrapped UUID signature.
func UUIDVerifier(secretKey []byte) VerifiableUUIDExtractor {
	return &uuidGenerator{
		secretKey: secretKey,
	}
}

// -----------------------------------------------------------------------------

type uuidGenerator struct {
	randReader io.Reader
	secretKey  []byte
	source     UUIDGeneratorFunc
}

func (vu *uuidGenerator) Generate(opts ...GenerateOption) (string, error) {
	// Prepare default settings
	dopts := &generateOption{}
	for _, o := range opts {
		o(dopts)
	}

	// Get an UUID from the source
	uuid, err := vu.source()
	if err != nil {
		return "", fmt.Errorf("unable to retrieve an UUID from the source: %w", err)
	}

	// Generate random nonce (96bits)
	var nonce [12]byte
	if _, err := io.ReadFull(vu.randReader, nonce[:]); err != nil {
		return "", fmt.Errorf("unable to generate random nonce: %w", err)
	}

	// Prepare token prefix
	prefix := ""
	if dopts.prefix != "" {
		// Ensure prefix syntax
		if nonAuthorizedChars.MatchString(dopts.prefix) {
			return "", fmt.Errorf("the given prefix %q contains forbidden characters, (0-9a-z-) are allowed", dopts.prefix)
		}
		prefix = dopts.prefix + defaultSeparator
	}

	// Derive a signature key to prevent direct secret key usages which could
	// threaten all generated tokens in the potential case of a secret leak.
	var authKey [32]byte
	h := hkdf.New(sha256.New, vu.secretKey, nonce[:], []byte("solid-uuid-wrapper-mac-v1"))
	if _, err := io.ReadFull(h, authKey[:]); err != nil {
		return "", fmt.Errorf("unable to derive authentication key: %w", err)
	}

	// Prepare protected
	protected := []byte("solid-uuid-protected-token-v1")
	protected = append(protected, []byte(prefix)...)
	protected = append(protected, uuid[:]...)

	// Prepare HMAC
	hm := hmac.New(sha256.New, authKey[:])
	hm.Write(protected)

	return prefix + toPaddedBase62(uuid[:], 22) + "_" + toPaddedBase62(hm.Sum(nonce[:]), 59), nil
}

func (vu *uuidGenerator) Verify(in string) error {
	_, err := vu.Extract(in)
	return err
}

func (vu *uuidGenerator) Extract(in string) ([]byte, error) {
	// Detect prefix usage
	var prefix string
	if parts := strings.SplitN(in, defaultSeparator, 3); len(parts) == 3 {
		prefix = parts[0] + defaultSeparator
		in = parts[1] + defaultSeparator + parts[2]
	}

	// Ensure a valid token format
	if !wrappedUUIDFormat.MatchString(in) {
		return nil, errors.New("invalid token format")
	}

	// Split token
	parts := strings.SplitN(in, "_", 2)

	// Decode UUID
	uuid, err := parsePaddedBase62(parts[0], 16)
	if err != nil {
		return nil, errors.New("invalid token syntax")
	}

	// Decode Nonce || Signature
	sig, err := parsePaddedBase62(parts[1], 44)
	if err != nil {
		return nil, errors.New("invalid token syntax")
	}

	// Derive a signature key to prevent direct secret key usages which could
	// threaten all generated tokens in the potential case of a secret leak.
	var authKey [32]byte
	h := hkdf.New(sha256.New, vu.secretKey, sig[:12], []byte("solid-uuid-wrapper-mac-v1"))
	if _, err := io.ReadFull(h, authKey[:]); err != nil {
		return nil, fmt.Errorf("unable to derive authentication key: %w", err)
	}

	// Prepare protected
	protected := []byte("solid-uuid-protected-token-v1")
	protected = append(protected, []byte(prefix)...)
	protected = append(protected, uuid[:]...)

	// Prepare HMAC
	hm := hmac.New(sha256.New, authKey[:])
	hm.Write(protected)

	// Compare signature
	if subtle.ConstantTimeCompare(sig[12:], hm.Sum(nil)) != 1 {
		return nil, ErrTokenNotAuthenticated
	}

	return uuid, nil
}
