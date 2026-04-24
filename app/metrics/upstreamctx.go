package metrics

import (
	"context"
	"time"
)

// WithUpstreamRoundtripStart stores the upstream handoff start time in the
// request context.
func WithUpstreamRoundtripStart(ctx context.Context, start time.Time) context.Context {
	return context.WithValue(ctx, upstreamRoundtripStartKey{}, start)
}

// UpstreamRoundtripStart retrieves the upstream handoff start time from the
// context if present.
func UpstreamRoundtripStart(ctx context.Context) (time.Time, bool) {
	v, ok := ctx.Value(upstreamRoundtripStartKey{}).(time.Time)
	return v, ok
}

type upstreamRoundtripStartKey struct{}
