package verifiable

import (
	"fmt"
	"math/big"
	"strings"
)

// https://ucarion.com/go-base62

func toPaddedBase62(input []byte, length int) string {
	var i big.Int
	i.SetBytes(input[:])
	return padLeft(i.Text(62), length)
}

func padLeft(in string, length int) string {
	if len(in) < length {
		in = strings.Repeat("0", length-len(in)) + in
	}

	return in
}

func parsePaddedBase62(s string, length int) ([]byte, error) {
	out := make([]byte, length)

	var i big.Int
	_, ok := i.SetString(s, 62)
	if !ok {
		return []byte{}, fmt.Errorf("cannot parse base62: %q", s)
	}

	return i.FillBytes(out), nil
}