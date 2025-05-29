package fsnotify

import (
	"os"
	"testing"
	"time"
)

func TestWatcherWriteRename(t *testing.T) {
	tmp, err := os.CreateTemp("", "watch*.txt")
	if err != nil {
		t.Fatal(err)
	}
	name := tmp.Name()
	tmp.Close()
	defer os.Remove(name)

	w, err := NewWatcher()
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()

	w.ticker.Stop()
	w.ticker = time.NewTicker(10 * time.Millisecond)

	if err := w.Add(name); err != nil {
		t.Fatal(err)
	}

	// modify
	if err := os.WriteFile(name, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	select {
	case ev := <-w.Events:
		if ev.Name != name || ev.Op != Write {
			t.Fatalf("unexpected event: %#v", ev)
		}
	case <-time.After(time.Second):
		t.Fatal("timeout waiting for write event")
	}

	// remove triggers rename
	if err := os.Remove(name); err != nil {
		t.Fatal(err)
	}
	select {
	case ev := <-w.Events:
		if ev.Name != name || ev.Op != Rename {
			t.Fatalf("unexpected event: %#v", ev)
		}
	case <-time.After(time.Second):
		t.Fatal("timeout waiting for rename event")
	}
}
