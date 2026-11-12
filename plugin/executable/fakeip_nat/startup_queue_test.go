package fakeipnat

import (
	"strings"
	"sync"
	"testing"
)

// TestStartupQueueRunsTasksInOrder keeps the ordering guarantee: a queued task
// never runs before Init returns, and the queue drains in the order it was
// filled, so a later cleanup cannot overtake an earlier one.
func TestStartupQueueRunsTasksInOrder(t *testing.T) {
	p := newTestPlugin(t, "198.18.0.0/16")

	var mu sync.Mutex
	var order []string
	record := func(name string) func() {
		return func() {
			mu.Lock()
			order = append(order, name)
			mu.Unlock()
		}
	}
	p.deferStartup("first", record("first"))
	p.deferStartup("second", record("second"))

	mu.Lock()
	queued := len(order)
	mu.Unlock()
	if queued != 0 {
		t.Fatalf("a queued task ran before the queue started")
	}

	p.startStartupQueue()
	p.startupWG.Wait()

	mu.Lock()
	defer mu.Unlock()
	if got := strings.Join(order, ","); got != "first,second" {
		t.Fatalf("queue order = %q, want first,second", got)
	}
}
