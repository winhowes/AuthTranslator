package fsnotify

import (
	"os"
	"sync"
	"time"
)

// Op describes a set of file operations.
type Op uint32

const (
	Write Op = 1 << iota
	Rename
)

type Event struct {
	Name string
	Op   Op
}

type Watcher struct {
	Events chan Event
	Errors chan error

	mu     sync.Mutex
	files  map[string]time.Time
	ticker *time.Ticker
	done   chan struct{}
}

// NewWatcher returns a new polling based watcher.
func NewWatcher() (*Watcher, error) {
	w := &Watcher{
		Events: make(chan Event, 10),
		Errors: make(chan error, 1),
		files:  make(map[string]time.Time),
		done:   make(chan struct{}),
	}
	w.ticker = time.NewTicker(time.Second)
	go w.loop()
	return w, nil
}

func (w *Watcher) loop() {
	for {
		select {
		case <-w.ticker.C:
			w.mu.Lock()
			for name, mod := range w.files {
				fi, err := os.Stat(name)
				if err != nil {
					// treat missing file as rename
					select {
					case w.Events <- Event{Name: name, Op: Rename}:
					default:
					}
					// remove missing file so event doesn't repeat
					delete(w.files, name)
					continue
				}
				if fi.ModTime().After(mod) {
					w.files[name] = fi.ModTime()
					select {
					case w.Events <- Event{Name: name, Op: Write}:
					default:
					}
				}
			}
			w.mu.Unlock()
		case <-w.done:
			w.ticker.Stop()
			close(w.Events)
			close(w.Errors)
			return
		}
	}
}

func (w *Watcher) Add(name string) error {
	fi, err := os.Stat(name)
	if err != nil {
		return err
	}
	w.mu.Lock()
	w.files[name] = fi.ModTime()
	w.mu.Unlock()
	return nil
}

func (w *Watcher) Remove(name string) error {
	w.mu.Lock()
	delete(w.files, name)
	w.mu.Unlock()
	return nil
}

func (w *Watcher) Close() error {
	select {
	case <-w.done:
	default:
		close(w.done)
	}
	return nil
}
