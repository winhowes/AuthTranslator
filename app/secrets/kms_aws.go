package secrets

// awsKMSPlugin is a stub for loading secrets from AWS KMS.
type awsKMSPlugin struct{}

func (awsKMSPlugin) Prefix() string { return "aws" }

func (awsKMSPlugin) Load(id string) (string, error) {
	// TODO: integrate with AWS KMS.
	return "aws-kms-" + id, nil
}

func init() { Register(awsKMSPlugin{}) }
