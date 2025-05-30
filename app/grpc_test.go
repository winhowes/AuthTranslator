package main

import (
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestProxyHandlerGRPC(t *testing.T) {
	upstream := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.ProtoMajor != 2 {
			t.Fatalf("expected HTTP/2, got %s", r.Proto)
		}
		w.Header().Set("Content-Type", "application/grpc")
		w.WriteHeader(http.StatusOK)
	}))
	upstream.EnableHTTP2 = true
	upstream.StartTLS()
	defer upstream.Close()

	integ := Integration{Name: "grpcint", Destination: upstream.URL, InRateLimit: 1, OutRateLimit: 1, TLSInsecureSkipVerify: true}
	if err := AddIntegration(&integ); err != nil {
		t.Fatalf("add integration: %v", err)
	}
	t.Cleanup(func() { integ.inLimiter.Stop(); integ.outLimiter.Stop() })

	proxy := httptest.NewUnstartedServer(http.HandlerFunc(proxyHandler))
	proxy.EnableHTTP2 = true
	proxy.StartTLS()
	defer proxy.Close()

	client := proxy.Client()
	client.Transport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: true}

	req, err := http.NewRequest(http.MethodPost, proxy.URL+"/", nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Host = "grpcint"
	req.Header.Set("Content-Type", "application/grpc")
	req.Header.Set("TE", "trailers")

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("do request: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
	if resp.ProtoMajor != 2 {
		t.Fatalf("expected HTTP/2 response, got %s", resp.Proto)
	}
}

func TestProxyHandlerGRPCHeaders(t *testing.T) {
	var gotCT, gotTE string
	upstream := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotCT = r.Header.Get("Content-Type")
		gotTE = r.Header.Get("TE")
		w.Header().Set("Content-Type", "application/grpc")
		w.WriteHeader(http.StatusOK)
	}))
	upstream.EnableHTTP2 = true
	upstream.StartTLS()
	defer upstream.Close()

	integ := Integration{Name: "grpchdr", Destination: upstream.URL, InRateLimit: 1, OutRateLimit: 1, TLSInsecureSkipVerify: true}
	if err := AddIntegration(&integ); err != nil {
		t.Fatalf("add integration: %v", err)
	}
	t.Cleanup(func() { integ.inLimiter.Stop(); integ.outLimiter.Stop() })

	proxy := httptest.NewUnstartedServer(http.HandlerFunc(proxyHandler))
	proxy.EnableHTTP2 = true
	proxy.StartTLS()
	defer proxy.Close()

	client := proxy.Client()
	client.Transport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: true}

	req, err := http.NewRequest(http.MethodPost, proxy.URL+"/", nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Host = "grpchdr"
	req.Header.Set("Content-Type", "application/grpc")
	req.Header.Set("TE", "trailers")

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("do request: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
	if gotCT != "application/grpc" {
		t.Fatalf("Content-Type not forwarded: %q", gotCT)
	}
	if gotTE != "trailers" {
		t.Fatalf("TE header not forwarded: %q", gotTE)
	}
}
