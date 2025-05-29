package authplugins

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
)

// MaxBodySize limits how many bytes GetBody will read. Applications may
// override this value to enforce a custom limit. A value of zero or negative
// disables the limit entirely.
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

	var reader io.Reader = r.Body
	if MaxBodySize > 0 {
		reader = io.LimitReader(r.Body, MaxBodySize+1)
	}

	b, err := io.ReadAll(reader)
	if err != nil {
		return nil, err
	}
	if MaxBodySize > 0 && int64(len(b)) > MaxBodySize {
		return nil, ErrBodyTooLarge
	}
	r.Body = io.NopCloser(bytes.NewReader(b))
	ctx := context.WithValue(r.Context(), bodyKey{}, b)
	*r = *r.WithContext(ctx)
	return b, nil
}
