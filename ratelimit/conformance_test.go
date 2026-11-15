package ratelimit_test

import (
	"testing"

	"github.com/kararnab/iam/v2/ratelimit"
	"github.com/kararnab/iam/v2/storetest"
)

// The conformance suite states Memory's semantics for every shared limiter.
func TestMemoryConformance(t *testing.T) {
	storetest.Limiter(t, func(t *testing.T, cfg ratelimit.Config) ratelimit.Limiter {
		l, err := ratelimit.NewMemory(cfg)
		if err != nil {
			t.Fatal(err)
		}
		return l
	})
}
