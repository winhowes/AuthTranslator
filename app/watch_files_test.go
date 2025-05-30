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

type mockWatcher struct {
	events chan fsnotify.Event
	errors chan error
	addErr error
}

func (m *mockWatcher) Add(name string) error         { return m.addErr }
func (m *mockWatcher) Close() error                  { close(m.events); close(m.errors); return nil }
func (m *mockWatcher) Events() <-chan fsnotify.Event { return m.events }
func (m *mockWatcher) Errors() <-chan error          { return m.errors }

func TestWatchFilesError(t *testing.T) {
	mw := &mockWatcher{events: make(chan fsnotify.Event), errors: make(chan error, 1)}
	old := newWatcher
	newWatcher = func() (fileWatcher, error) { return mw, nil }
	defer func() { newWatcher = old }()

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { watchFiles(ctx, nil, make(chan struct{})); close(done) }()
	mw.errors <- fmt.Errorf("boom")
	cancel()
	<-done
}

func TestWatchFilesRenameAddError(t *testing.T) {
	mw := &mockWatcher{events: make(chan fsnotify.Event, 1), errors: make(chan error), addErr: fmt.Errorf("fail")}
	old := newWatcher
	newWatcher = func() (fileWatcher, error) { return mw, nil }
	defer func() { newWatcher = old }()

	ch := make(chan struct{}, 1)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { watchFiles(ctx, []string{"f"}, ch); close(done) }()
	mw.events <- fsnotify.Event{Name: "f", Op: fsnotify.Rename}
	select {
	case <-ch:
	case <-time.After(time.Second):
		t.Fatal("timeout waiting for event")
	}
	cancel()
	<-done
}
