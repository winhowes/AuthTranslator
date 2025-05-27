package plugins

import "github.com/winhowes/AuthTranslator/app/secrets"

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"time"
)

// azureKMSPlugin retrieves secrets from Azure Key Vault. It uses the
// client credentials flow to obtain an access token from Azure AD and
// then fetches the secret via the Key Vault REST API. The secret
// identifier should be the full URL of the secret without any
// query parameters (e.g. "https://myvault.vault.azure.net/secrets/foo").
type azureKMSPlugin struct{}

var HTTPClient = &http.Client{Timeout: 5 * time.Second}

// Prefix returns the identifier prefix used in configuration strings.
func (azureKMSPlugin) Prefix() string { return "azure" }

// Load resolves the secret identified by id using Azure Key Vault. The
// plugin expects a service principal to be configured via the environment
// variables AZURE_TENANT_ID, AZURE_CLIENT_ID and AZURE_CLIENT_SECRET.
func (azureKMSPlugin) Load(id string) (string, error) {
	tenantID := os.Getenv("AZURE_TENANT_ID")
	clientID := os.Getenv("AZURE_CLIENT_ID")
	clientSecret := os.Getenv("AZURE_CLIENT_SECRET")
	if tenantID == "" || clientID == "" || clientSecret == "" {
		return "", errors.New("missing azure credentials")
	}

	token, err := getAzureToken(tenantID, clientID, clientSecret)
	if err != nil {
		return "", err
	}

	req, err := http.NewRequest("GET", id+"?api-version=7.2", nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := HTTPClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("failed to fetch secret: %s", resp.Status)
	}

	var out struct {
		Value string `json:"value"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return "", err
	}
	return out.Value, nil
}

func getAzureToken(tenant, client, secret string) (string, error) {
	form := url.Values{}
	form.Set("grant_type", "client_credentials")
	form.Set("client_id", client)
	form.Set("client_secret", secret)
	form.Set("scope", "https://vault.azure.net/.default")

	u := fmt.Sprintf("https://login.microsoftonline.com/%s/oauth2/v2.0/token", tenant)
	req, err := http.NewRequest("POST", u, bytes.NewBufferString(form.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := HTTPClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("token request failed: %s", resp.Status)
	}
	var out struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return "", err
	}
	return out.AccessToken, nil
}

func init() { secrets.Register(azureKMSPlugin{}) }
