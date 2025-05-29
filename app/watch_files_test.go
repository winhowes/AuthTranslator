package main

import (
	"context"
	"os"
	"testing"
	"time"
)

func TestWatchFiles(t *testing.T) {
	tmp, err := os.CreateTemp("", "watch*.json")
	if err != nil {
		t.Fatal(err)
	}
	name := tmp.Name()
	tmp.Close()
	defer os.Remove(name)

	ch := make(chan struct{}, 1)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go watchFiles(ctx, []string{name}, ch)

	// give watcher time to start
	time.Sleep(20 * time.Millisecond)

	if err := os.WriteFile(name, []byte("1"), 0o644); err != nil {
		t.Fatal(err)
	}

	select {
	case <-ch:
		// success
	case <-time.After(time.Second):
		t.Fatal("timeout waiting for event")
	}
}
