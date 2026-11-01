package brute

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"subsoil/internal/dnsx"
	"subsoil/internal/model"
	"subsoil/internal/testutil"
)

func TestProgressCountsFilteredAttempts(t *testing.T) {
	z := testutil.NewZone("wild.test")
	z.Add("wild.test. 300 IN A 192.0.2.1")
	z.Add("hit0.wild.test. 300 IN A 192.0.2.50")
	z.SetWildcard("*.wild.test. 300 IN A 192.0.2.99")
	addr := z.Start(t)

	r, err := dnsx.New([]string{addr}, 2*time.Second, 0)
	if err != nil {
		t.Fatal(err)
	}

	words := []string{"hit0"}
	for i := 0; i < 599; i++ {
		words = append(words, fmt.Sprintf("n%d", i))
	}

	var (
		mu       sync.Mutex
		calls    int
		lastDone int
		lastHits int
	)
	res := Run(context.Background(), r, "wild.test", words, Options{
		Workers:  8,
		Wildcard: model.Wildcard{Enabled: true, IPs: []string{"192.0.2.99"}},
		Progress: func(done, total, hits int) {
			mu.Lock()
			defer mu.Unlock()
			calls++
			lastDone = done
			lastHits = hits
		},
	})

	mu.Lock()
	defer mu.Unlock()
	if res.Tried != len(words) {
		t.Fatalf("Tried = %d, want %d", res.Tried, len(words))
	}
	if res.Hits != 1 {
		t.Fatalf("Hits = %d, want 1", res.Hits)
	}
	if res.WildcardDrops != len(words)-1 {
		t.Fatalf("WildcardDrops = %d, want %d", res.WildcardDrops, len(words)-1)
	}
	if calls == 0 || lastDone != len(words) {
		t.Fatalf("progress calls=%d lastDone=%d, want final %d", calls, lastDone, len(words))
	}
	if lastHits != 1 {
		t.Fatalf("final progress hits = %d, want 1", lastHits)
	}
}
