package randomness

import (
	"sync"
	"testing"
)

// TestConcurrentGlobal exercises the rand API concurrently, triggering situations
// where the race detector is likely to detect issues.
func TestConcurrentGlobal(t *testing.T) {
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
			buf := make([]byte, 997)
			for j := 0; j < numCycles; j++ {
				var seed int64
				seed += int64(ExpFloat64())
				seed += int64(Float32())
				seed += int64(Float64())
				seed += int64(NormFloat64())
				seed += int64(Intn(Int()))
				seed += int64(Int31n(Int31()))
				seed += Int63n(Int63())
				seed += int64(Uint32())
				seed += int64(Uint64())
				for _, p := range Perm(10) {
					seed += int64(p)
				}
				for _, b := range buf {
					seed += int64(b)
				}
			}
		}()
	}
}

func TestShuffleGlobal(t *testing.T) {
	t.Parallel()

	// Check that Shuffle allows n=0 and n=1, but that swap is never called for them.
	for n := 0; n <= 1; n++ {
		Shuffle(n, func(i, j int) { t.Fatalf("swap called, n=%d i=%d j=%d", n, i, j) })
	}
}
