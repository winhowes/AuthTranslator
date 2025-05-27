package secrets

// gcpKMSPlugin is a stub for loading secrets from Google Cloud KMS.
type gcpKMSPlugin struct{}

func (gcpKMSPlugin) Prefix() string { return "gcp" }

func (gcpKMSPlugin) Load(id string) (string, error) {
	// TODO: integrate with Google Cloud KMS.
	return "gcp-kms-" + id, nil
}

func init() { Register(gcpKMSPlugin{}) }
