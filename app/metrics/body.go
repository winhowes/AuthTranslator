package metrics

import (
	"bytes"
	"io"
	"net/http"
)

// GetResponseBody returns the response body bytes and resets resp.Body so it can
// be read again. It closes the original body to allow connection reuse.
func GetResponseBody(resp *http.Response) ([]byte, error) {
	if resp == nil || resp.Body == nil {
		return nil, nil
	}
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	resp.Body.Close()
	resp.Body = io.NopCloser(bytes.NewReader(data))
	resp.ContentLength = int64(len(data))
	return data, nil
}
