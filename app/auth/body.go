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
type readCloseMulti struct {
	io.Reader
	io.Closer
}

func (rcm readCloseMulti) Close() error {
	if rcm.Closer != nil {
		return rcm.Closer.Close()
	}
	return nil
}

func GetBody(r *http.Request) ([]byte, error) {
	if b, ok := r.Context().Value(bodyKey{}).([]byte); ok {
		return b, nil
	}

	orig := r.Body
	if orig == nil {
		orig = http.NoBody
	}
	var reader io.Reader = orig
	if MaxBodySize > 0 {
		reader = io.LimitReader(orig, MaxBodySize+1)
	}

	b, err := io.ReadAll(reader)
	// restore the consumed bytes so callers can read the body even on error
	r.Body = &readCloseMulti{Reader: io.MultiReader(bytes.NewReader(b), orig), Closer: orig}
	if err != nil {
		return nil, err
	}
	if MaxBodySize > 0 && int64(len(b)) > MaxBodySize {
		return nil, ErrBodyTooLarge
	}
	ctx := context.WithValue(r.Context(), bodyKey{}, b)
	*r = *r.WithContext(ctx)
	return b, nil
}
