package authplugins

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
)

// MaxBodySize limits how many bytes GetBody will read. It can be overridden
// by applications to enforce a custom limit.
var MaxBodySize int64 = 10 << 20 // 10MB

// ErrBodyTooLarge is returned when a request body exceeds MaxBodySize.
var ErrBodyTooLarge = errors.New("body too large")

type bodyKey struct{}

// GetBody returns the request body bytes while caching the result for
// subsequent calls. It also resets r.Body so callers can read it again.
func GetBody(r *http.Request) ([]byte, error) {
	if b, ok := r.Context().Value(bodyKey{}).([]byte); ok {
		return b, nil
	}
	lr := io.LimitReader(r.Body, MaxBodySize+1)
	b, err := io.ReadAll(lr)
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > MaxBodySize {
		return nil, ErrBodyTooLarge
	}
	r.Body = io.NopCloser(bytes.NewReader(b))
	ctx := context.WithValue(r.Context(), bodyKey{}, b)
	*r = *r.WithContext(ctx)
	return b, nil
}
