package statusmetric

import (
	"net/http"

	"github.com/winhowes/AuthTranslator/app/metrics"
)

type statusMetric struct{}

func (*statusMetric) OnRequest(string, *http.Request) {}

func (*statusMetric) OnResponse(integration, caller string, r *http.Request, resp *http.Response) {
	metrics.RecordStatus(integration, resp.StatusCode)
}

func (*statusMetric) WriteProm(http.ResponseWriter) {}

func init() { metrics.Register(&statusMetric{}) }
