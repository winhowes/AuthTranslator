package plugins

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/winhowes/AuthTranslator/app/secrets"
)

// vaultPlugin fetches secrets from HashiCorp Vault using the HTTP API.
// The identifier should be the path to the secret within Vault, e.g.
// "secret/data/myapp" for KVv2.
// It requires the VAULT_ADDR and VAULT_TOKEN environment variables.
type vaultPlugin struct{}

// HTTPClient is used for requests to Vault and can be overridden in tests.
var HTTPClient = &http.Client{Timeout: 5 * time.Second}

func (vaultPlugin) Prefix() string { return "vault" }

func (vaultPlugin) Load(ctx context.Context, id string) (string, error) {
	addr := os.Getenv("VAULT_ADDR")
	token := os.Getenv("VAULT_TOKEN")
	if addr == "" || token == "" {
		return "", errors.New("missing vault configuration")
	}

	base, err := url.Parse(addr)
	if err != nil {
		return "", fmt.Errorf("invalid VAULT_ADDR: %w", err)
	}
	path := strings.TrimLeft(id, "/")
	base.Path = "/v1/" + path
	req, err := http.NewRequest("GET", base.String(), nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("X-Vault-Token", token)
	resp, err := HTTPClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("vault request failed: %s", resp.Status)
	}

	var out struct {
		Data struct {
			Value string            `json:"value"`
			Data  map[string]string `json:"data"`
		} `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return "", err
	}

	if out.Data.Value != "" {
		return out.Data.Value, nil
	}
	if val, ok := out.Data.Data["value"]; ok {
		return val, nil
	}
	return "", errors.New("secret value missing")
}

func init() { secrets.Register(vaultPlugin{}) }
