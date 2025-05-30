package main

import (
	"context"
	"os"
	"testing"
	"time"
)

func TestWatchFiles(t *testing.T) {
	tmp, err := os.CreateTemp("", "watch*.yaml")
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
	time.Sleep(50 * time.Millisecond)

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

func TestWatchFilesRename(t *testing.T) {
	tmp, err := os.CreateTemp("", "watch*.yaml")
	if err != nil {
		t.Fatal(err)
	}
	name := tmp.Name()
	tmp.Close()
	defer os.Remove(name)

	ch := make(chan struct{}, 2)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go watchFiles(ctx, []string{name}, ch)

	// allow watcher to start
	time.Sleep(50 * time.Millisecond)

	// rename the file to trigger an event and remove the watch
	newName := name + ".old"
	if err := os.Rename(name, newName); err != nil {
		t.Fatal(err)
	}

	select {
	case <-ch:
		// rename event delivered
	case <-time.After(time.Second):
		t.Fatal("timeout waiting for rename event")
	}

	// recreate the original file and modify it; watcher should fire again
	if err := os.WriteFile(name, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	// give watcher time to re-add
	time.Sleep(50 * time.Millisecond)
	if err := os.WriteFile(name, []byte("y"), 0o644); err != nil {
		t.Fatal(err)
	}

	select {
	case <-ch:
		// modification detected
	case <-time.After(time.Second):
		t.Fatal("timeout waiting for write event after rename")
	}
}

func TestWatchFilesCancel(t *testing.T) {
	ch := make(chan struct{}, 1)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		watchFiles(ctx, []string{"/path/does/not/exist"}, ch)
		close(done)
	}()
	// let goroutine start
	time.Sleep(50 * time.Millisecond)
	cancel()
	select {
	case <-done:
		// success
	case <-time.After(time.Second):
		t.Fatal("watchFiles did not exit after cancel")
	}
}

func TestWatchFilesAddError(t *testing.T) {
	tmp, err := os.CreateTemp("", "watch*.yaml")
	if err != nil {
		t.Fatal(err)
	}
	name := tmp.Name()
	tmp.Close()
	defer os.Remove(name)

	missing := name + ".missing"

	ch := make(chan struct{}, 1)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go watchFiles(ctx, []string{name, missing}, ch)

	time.Sleep(50 * time.Millisecond)

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
