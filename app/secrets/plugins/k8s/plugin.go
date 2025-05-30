package plugins

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/winhowes/AuthTranslator/app/secrets"
)

// k8sPlugin retrieves secrets from the Kubernetes API using the
// service account credentials available when running inside a
// cluster. The identifier has the form "<namespace>/<name>#<key>".
// The secret data is assumed to be base64 encoded as returned by the
// Kubernetes API.
type k8sPlugin struct{}

var (
	httpClient = &http.Client{Timeout: 5 * time.Second}
	tokenPath  = "/var/run/secrets/kubernetes.io/serviceaccount/token"
	caPath     = "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"

	readFile   = os.ReadFile
	newRequest = http.NewRequestWithContext
)

func (k8sPlugin) Prefix() string { return "k8s" }

func (k8sPlugin) Load(ctx context.Context, id string) (string, error) {
	parts := strings.SplitN(id, "#", 2)
	if len(parts) != 2 {
		return "", fmt.Errorf("invalid k8s id: %s", id)
	}
	secretRef, key := parts[0], parts[1]
	nsName := strings.SplitN(secretRef, "/", 2)
	if len(nsName) != 2 || nsName[0] == "" || nsName[1] == "" || key == "" {
		return "", fmt.Errorf("invalid k8s id: %s", id)
	}
	namespace, name := nsName[0], nsName[1]

	host := os.Getenv("KUBERNETES_SERVICE_HOST")
	port := os.Getenv("KUBERNETES_SERVICE_PORT")
	if host == "" || port == "" {
		return "", fmt.Errorf("not running in a cluster")
	}

	token, err := readFile(tokenPath)
	if err != nil {
		return "", err
	}
	caData, err := readFile(caPath)
	if err != nil {
		return "", err
	}

	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(caData)

	client := httpClient
	if client.Transport == nil {
		client = &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool}}, Timeout: client.Timeout}
	}

	url := fmt.Sprintf("https://%s:%s/api/v1/namespaces/%s/secrets/%s", host, port, namespace, name)
	req, err := newRequest(ctx, "GET", url, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(string(token)))

	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("k8s request failed: %s: %s", resp.Status, body)
	}
	var out struct {
		Data map[string]string `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return "", err
	}
	valB64, ok := out.Data[key]
	if !ok {
		return "", fmt.Errorf("key %s not found in secret %s/%s", key, namespace, name)
	}
	val, err := base64.StdEncoding.DecodeString(valB64)
	if err != nil {
		return "", err
	}
	return string(val), nil
}

func init() { secrets.Register(k8sPlugin{}) }
