package randomness

import (
	"sync"
	"testing"
)

// TestConcurrentLockedRand exercises the rand API concurrently, triggering situations
// where the race detector is likely to detect issues.
//
//nolint:errcheck
func TestConcurrentLockedRand(t *testing.T) {
	t.Parallel()

	const (
		numRoutines = 10
		numCycles   = 10
	)

	r := NewLockedRand(1)

	var wg sync.WaitGroup
	defer wg.Wait()
	wg.Add(numRoutines)
	for i := 0; i < numRoutines; i++ {
		go func(i int) {
			defer wg.Done()
			buf := make([]byte, 997)
			for j := 0; j < numCycles; j++ {
				var seed int64
				seed += int64(r.ExpFloat64())
				seed += int64(r.Float32())
				seed += int64(r.Float64())
				seed += int64(r.NormFloat64())
				seed += int64(r.Intn(r.Int()))
				seed += int64(r.Int31n(r.Int31()))
				seed += r.Int63n(r.Int63())
				seed += int64(r.Uint32())
				seed += int64(r.Uint64())
				for _, p := range r.Perm(10) {
					seed += int64(p)
				}
				r.Read(buf)
				for _, b := range buf {
					seed += int64(b)
				}
				r.Seed(int64(i*j) * seed)
			}
		}(i)
	}
}

func TestShuffleSmall(t *testing.T) {
	t.Parallel()

	// Check that Shuffle allows n=0 and n=1, but that swap is never called for them.
	r := NewLockedRand(1)
	for n := 0; n <= 1; n++ {
		r.Shuffle(n, func(i, j int) { t.Fatalf("swap called, n=%d i=%d j=%d", n, i, j) })
	}
}