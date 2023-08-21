package randomness

import (
	"io"
	"sync"
	"testing"
)

func BenchmarkReader(b *testing.B) {
	b.Run("1", benchmarkReader(1))
	b.Run("512", benchmarkReader(512))
	b.Run("1024", benchmarkReader(1024))
	b.Run("2048", benchmarkReader(2048))
	b.Run("4096", benchmarkReader(4096))
}

//nolint:errcheck
func benchmarkReader(inputLen int) func(b *testing.B) {
	return func(b *testing.B) {
		b.ReportAllocs()

		for i := 0; i < b.N; i++ {
			b.SetBytes(int64(inputLen))
			io.CopyN(io.Discard, Reader, int64(inputLen))
		}
	}
}

// TestConcurrent exercises the rand API concurrently, triggering situations
// where the race detector is likely to detect issues.
//
//nolint:errcheck
func TestConcurrentReader(t *testing.T) {
	t.Parallel()

	const (
		numRoutines = 10
		numCycles   = 10
	)
	var wg sync.WaitGroup
	defer wg.Wait()
	wg.Add(numRoutines)
	for i := 0; i < numRoutines; i++ {
		go func() {
			defer wg.Done()
			for j := 0; j < numCycles; j++ {
				io.CopyN(io.Discard, Reader, 1024)
			}
		}()
	}
}