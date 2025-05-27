package authplugins

import (
	"bytes"
	"context"
	"io"
	"net/http"
)

type bodyKey struct{}

// GetBody returns the request body bytes while caching the result for
// subsequent calls. It also resets r.Body so callers can read it again.
func GetBody(r *http.Request) ([]byte, error) {
	if b, ok := r.Context().Value(bodyKey{}).([]byte); ok {
		return b, nil
	}
	b, err := io.ReadAll(r.Body)
	if err != nil {
		return nil, err
	}
	r.Body = io.NopCloser(bytes.NewReader(b))
	ctx := context.WithValue(r.Context(), bodyKey{}, b)
	*r = *r.WithContext(ctx)
	return b, nil
}
