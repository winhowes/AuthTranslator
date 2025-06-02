package durationrecorder

import (
	"context"
	"net/http"
	"time"

	"github.com/winhowes/AuthTranslator/app/metrics"
)

type durationRecorder struct{}

type startKey struct{}

func (*durationRecorder) OnRequest(integration string, r *http.Request) {
	ctx := context.WithValue(r.Context(), startKey{}, time.Now())
	*r = *r.WithContext(ctx)
}

func (*durationRecorder) OnResponse(integration, caller string, r *http.Request, resp *http.Response) {
	if t, ok := r.Context().Value(startKey{}).(time.Time); ok {
		metrics.RecordDuration(integration, time.Since(t))
	}
}

func (*durationRecorder) WriteProm(http.ResponseWriter) {}

func init() { metrics.Register(&durationRecorder{}) }
