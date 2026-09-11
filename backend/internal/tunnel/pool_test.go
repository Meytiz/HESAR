package tunnel

import (
	"context"
	"testing"
	"time"
)

func TestConnPoolBoundsConcurrentHandshakes(t *testing.T) {
	p := NewConnPool(2)
	if p.Cap() != 2 {
		t.Fatalf("Cap() = %d, want 2", p.Cap())
	}

	for i := 0; i < 2; i++ {
		if err := p.Acquire(context.Background()); err != nil {
			t.Fatalf("Acquire %d: %v", i, err)
		}
	}
	if p.InUse() != 2 {
		t.Fatalf("InUse() = %d, want 2", p.InUse())
	}

	// The pool is saturated: a third Acquire must not succeed. It has to
	// block and then surface the context deadline — this is exactly the
	// back-pressure behaviour the accept loops rely on.
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if err := p.Acquire(ctx); err == nil {
		t.Fatal("Acquire on a saturated pool must block until the context expires")
	}

	// After a Release the slot is reusable again.
	p.Release()
	if err := p.Acquire(context.Background()); err != nil {
		t.Fatalf("Acquire after Release: %v", err)
	}
	if p.InUse() != 2 {
		t.Fatalf("InUse() = %d, want 2", p.InUse())
	}
}

// A stopped tunnel must never leave goroutines parked in Acquire forever:
// cancelling the handler context has to unblock them.
func TestConnPoolAcquireUnblocksOnCancel(t *testing.T) {
	p := NewConnPool(1)
	if err := p.Acquire(context.Background()); err != nil {
		t.Fatalf("first Acquire: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- p.Acquire(ctx) }()

	cancel()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("blocked Acquire must return an error once its context is cancelled")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("blocked Acquire did not return after context cancellation")
	}
}

func TestNewConnPoolHonoursEnvOverride(t *testing.T) {
	t.Setenv(envMaxConcurrentHandshakes, "7")
	if got := NewConnPool(0).Cap(); got != 7 {
		t.Fatalf("env override ignored: Cap() = %d, want 7", got)
	}
	// An explicit positive size always wins over the env override.
	if got := NewConnPool(3).Cap(); got != 3 {
		t.Fatalf("explicit size ignored: Cap() = %d, want 3", got)
	}
}

func TestNewConnPoolRejectsGarbageEnvValue(t *testing.T) {
	t.Setenv(envMaxConcurrentHandshakes, "not-a-number")
	if got := NewConnPool(0).Cap(); got != DefaultMaxConcurrentHandshakes {
		t.Fatalf("garbage env value must fall back to the default: Cap() = %d, want %d", got, DefaultMaxConcurrentHandshakes)
	}
}
