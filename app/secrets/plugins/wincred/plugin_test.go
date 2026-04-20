package plugins

import (
	"context"
	"testing"
)

func TestWinCredPluginLoad(t *testing.T) {
	p := winCredPlugin{}
	_, err := p.Load(context.Background(), "my-target")
	if err == nil {
		t.Fatal("expected wincred loader error on non-windows test environment")
	}
}
