package plugins

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/winhowes/AuthTranslator/app/secrets"
)

// gcpKMSPlugin loads secrets from Google Cloud KMS. The identifier should be in
// the form "projects/.../locations/.../keyRings/.../cryptoKeys/...:ciphertext"
// where the part after the colon is a base64 encoded ciphertext produced by
// Google Cloud KMS. The plugin uses the metadata server for authentication,
// which means it only works when running on GCP with a service account
// attached.
type gcpKMSPlugin struct{}

var HTTPClient = &http.Client{Timeout: 5 * time.Second}

// helpers overridable in tests
var (
	httpNewRequest = http.NewRequest
	jsonMarshal    = json.Marshal
)

func (gcpKMSPlugin) Prefix() string { return "gcp" }

func (gcpKMSPlugin) Load(ctx context.Context, id string) (string, error) {
	parts := strings.SplitN(id, ":", 2)
	if len(parts) != 2 {
		return "", fmt.Errorf("invalid gcp kms id: %s", id)
	}
	keyName, ciphertext := parts[0], parts[1]

	// Obtain an access token from the metadata server.
	req, err := httpNewRequest("GET", "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token", nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Metadata-Flavor", "Google")
	resp, err := HTTPClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("metadata token request failed: %s: %s", resp.Status, body)
	}
	var tr struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&tr); err != nil {
		return "", err
	}

	// Call the KMS API to decrypt the ciphertext.
	decryptURL := fmt.Sprintf("https://cloudkms.googleapis.com/v1/%s:decrypt", keyName)
	body, err := jsonMarshal(map[string]string{"ciphertext": ciphertext})
	if err != nil {
		return "", err
	}

	postReq, err := httpNewRequest("POST", decryptURL, bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	postReq.Header.Set("Authorization", "Bearer "+tr.AccessToken)
	postReq.Header.Set("Content-Type", "application/json")

	resp2, err := HTTPClient.Do(postReq)
	if err != nil {
		return "", err
	}
	defer resp2.Body.Close()
	if resp2.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp2.Body)
		return "", fmt.Errorf("kms decrypt failed: %s: %s", resp2.Status, body)
	}
	var dr struct {
		Plaintext string `json:"plaintext"`
	}
	if err := json.NewDecoder(resp2.Body).Decode(&dr); err != nil {
		return "", err
	}
	plaintext, err := base64.StdEncoding.DecodeString(dr.Plaintext)
	if err != nil {
		return "", err
	}
	return string(plaintext), nil
}

func init() { secrets.Register(gcpKMSPlugin{}) }
