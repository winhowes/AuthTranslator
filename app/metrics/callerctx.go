package metrics

import "context"

// WithCaller returns a new context with the caller ID stored.
func WithCaller(ctx context.Context, caller string) context.Context {
	return context.WithValue(ctx, callerKey{}, caller)
}

// Caller retrieves the caller ID from the context if present.
func Caller(ctx context.Context) string {
	if v, ok := ctx.Value(callerKey{}).(string); ok {
		return v
	}
	return ""
}

// callerKey is unexported to avoid collisions.
type callerKey struct{}
