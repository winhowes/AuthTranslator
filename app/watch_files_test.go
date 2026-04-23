package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
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

	// recreate the original file and modify it; the directory watch should fire again
	if err := os.WriteFile(name, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	// give the filesystem time to deliver the create event before the write
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

func TestWatchFilesKubernetesSymlinkSwap(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("projected-volume symlink semantics are Unix-specific")
	}

	dir := t.TempDir()
	writeProjectedConfig(t, dir, 1, "one", true)
	name := filepath.Join(dir, "config.yaml")

	ch := make(chan struct{}, 2)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go watchFiles(ctx, []string{name}, ch)

	// give watcher time to start
	time.Sleep(50 * time.Millisecond)

	writeProjectedConfig(t, dir, 2, "two", false)

	select {
	case <-ch:
		// symlink swap detected
	case <-time.After(time.Second):
		t.Fatal("timeout waiting for projected volume update")
	}
}

func writeProjectedConfig(t *testing.T, dir string, rev int, contents string, createFileLink bool) {
	t.Helper()

	dataDir := filepath.Join(dir, fmt.Sprintf("..2026_01_01_00_00_%02d.000000000", rev))
	if err := os.Mkdir(dataDir, 0o755); err != nil {
		t.Fatalf("mkdir projected data dir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dataDir, "config.yaml"), []byte(contents), 0o644); err != nil {
		t.Fatalf("write projected config: %v", err)
	}

	tmpLink := filepath.Join(dir, "..data_tmp")
	dataLink := filepath.Join(dir, "..data")
	if err := os.Remove(tmpLink); err != nil && !os.IsNotExist(err) {
		t.Fatalf("remove stale projected tmp link: %v", err)
	}
	if err := os.Symlink(filepath.Base(dataDir), tmpLink); err != nil {
		t.Fatalf("create projected tmp link: %v", err)
	}
	if err := os.Rename(tmpLink, dataLink); err != nil {
		t.Fatalf("swap projected data link: %v", err)
	}

	if createFileLink {
		if err := os.Symlink(filepath.Join("..data", "config.yaml"), filepath.Join(dir, "config.yaml")); err != nil {
			t.Fatalf("create projected config link: %v", err)
		}
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

func TestWatchFilesDebouncesBurst(t *testing.T) {
	mw := &mockWatcher{events: make(chan fsnotify.Event, 2), errors: make(chan error)}
	old := newWatcher
	newWatcher = func() (fileWatcher, error) { return mw, nil }
	defer func() { newWatcher = old }()

	name := filepath.Join(t.TempDir(), "config.yaml")
	ch := make(chan struct{}, 2)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() { watchFiles(ctx, []string{name}, ch); close(done) }()
	mw.events <- fsnotify.Event{Name: name, Op: fsnotify.Write}
	mw.events <- fsnotify.Event{Name: name, Op: fsnotify.Write}

	select {
	case <-ch:
		// success
	case <-time.After(time.Second):
		t.Fatal("timeout waiting for debounced event")
	}

	select {
	case <-ch:
		t.Fatal("expected burst events to be coalesced")
	case <-time.After(2*watchDebounceDelay + 50*time.Millisecond):
	}
	cancel()
	<-done
}

func TestWatchFilesAddError(t *testing.T) {
	mw := &mockWatcher{events: make(chan fsnotify.Event), errors: make(chan error), addErr: fmt.Errorf("boom")}
	old := newWatcher
	newWatcher = func() (fileWatcher, error) { return mw, nil }
	defer func() { newWatcher = old }()

	ch := make(chan struct{}, 1)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { watchFiles(ctx, []string{"f"}, ch); close(done) }()
	time.Sleep(50 * time.Millisecond)
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("watchFiles did not exit after add error")
	}
}

func TestWatchFilesNewWatcherError(t *testing.T) {
	old := newWatcher
	newWatcher = func() (fileWatcher, error) { return nil, fmt.Errorf("fail") }
	defer func() { newWatcher = old }()

	done := make(chan struct{})
	go func() { watchFiles(context.Background(), nil, make(chan struct{})); close(done) }()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("watchFiles did not exit on watcher error")
	}
}
