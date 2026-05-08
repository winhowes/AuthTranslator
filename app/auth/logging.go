package authplugins

import (
	"io"
	"log/slog"
	"sync"
)

var (
	discardLogger = slog.New(slog.NewTextHandler(io.Discard, nil))
	loggerMu      sync.RWMutex
	logger        = discardLogger
)

// SetLogger sets the logger used by auth plugins and returns the previous one.
func SetLogger(l *slog.Logger) *slog.Logger {
	if l == nil {
		l = discardLogger
	}
	loggerMu.Lock()
	defer loggerMu.Unlock()
	prev := logger
	logger = l
	return prev
}

// Logger returns the logger used by auth plugins.
func Logger() *slog.Logger {
	loggerMu.RLock()
	defer loggerMu.RUnlock()
	return logger
}
