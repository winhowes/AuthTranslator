package main

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/fsnotify/fsnotify"
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

// fakeWatcher is a minimal implementation of fileWatcher used for testing.
type fakeWatcher struct {
	events chan fsnotify.Event
	errors chan error
	addErr error
}

func (f *fakeWatcher) Add(string) error              { return f.addErr }
func (f *fakeWatcher) Close() error                  { return nil }
func (f *fakeWatcher) Events() <-chan fsnotify.Event { return f.events }
func (f *fakeWatcher) Errors() <-chan error          { return f.errors }

func TestWatchFilesWatcherError(t *testing.T) {
	fw := &fakeWatcher{
		events: make(chan fsnotify.Event),
		errors: make(chan error, 1),
	}
	oldNew := newWatcher
	newWatcher = func() (fileWatcher, error) { return fw, nil }
	defer func() { newWatcher = oldNew }()

	ch := make(chan struct{}, 1)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		watchFiles(ctx, []string{"dummy"}, ch)
		close(done)
	}()
	fw.errors <- fmt.Errorf("boom")
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("watchFiles did not exit")
	}
}

func TestWatchFilesChannelFull(t *testing.T) {
	tmp, err := os.CreateTemp("", "watch*.txt")
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
	time.Sleep(50 * time.Millisecond)

	if err := os.WriteFile(name, []byte("1"), 0o644); err != nil {
		t.Fatal(err)
	}
	// wait for first event
	select {
	case <-ch:
	case <-time.After(time.Second):
		t.Fatal("timeout waiting for first event")
	}

	// do not drain channel, write again
	if err := os.WriteFile(name, []byte("2"), 0o644); err != nil {
		t.Fatal(err)
	}
	time.Sleep(100 * time.Millisecond)
	if len(ch) != 1 {
		t.Fatalf("expected channel size 1, got %d", len(ch))
	}
	<-ch // drain
	if err := os.WriteFile(name, []byte("3"), 0o644); err != nil {
		t.Fatal(err)
	}
	select {
	case <-ch:
	case <-time.After(time.Second):
		t.Fatal("timeout waiting for second event")
	}
}
