package randomness

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
)

// CryptoSeed returns a seed using crypto/rand. On error, the function generates
// a panic with the error.
func CryptoSeed() int64 {
	var i64Bytes [8]byte
	_, err := rand.Read(i64Bytes[:])
	if err != nil {
		panic(fmt.Errorf("failed to initialize the crypto/rand seed: %v", err))
	}
	return int64(binary.LittleEndian.Uint64(i64Bytes[:]))
}
