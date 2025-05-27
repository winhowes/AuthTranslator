package plugins

import "github.com/winhowes/AuthTransformer/app/secrets"

// azureKMSPlugin is a stub for loading secrets from Azure Key Vault.
type azureKMSPlugin struct{}

func (azureKMSPlugin) Prefix() string { return "azure" }

func (azureKMSPlugin) Load(id string) (string, error) {
	// TODO: integrate with Azure Key Vault.
	return "azure-kms-" + id, nil
}

func init() { secrets.Register(azureKMSPlugin{}) }
