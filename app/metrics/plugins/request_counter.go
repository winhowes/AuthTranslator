package plugins

import (
	"net/http"

	"github.com/winhowes/AuthTranslator/app/metrics"
)

type requestCounter struct{}

func (*requestCounter) OnRequest(integration string, r *http.Request) {
	metrics.IncRequest(integration)
}

func (*requestCounter) OnResponse(string, string, *http.Request, *http.Response) {}

func init() { metrics.Register(&requestCounter{}) }
