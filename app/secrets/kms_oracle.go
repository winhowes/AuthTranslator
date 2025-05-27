package secrets

// oracleKMSPlugin is a stub for loading secrets from Oracle Cloud KMS.
type oracleKMSPlugin struct{}

func (oracleKMSPlugin) Prefix() string { return "oracle" }

func (oracleKMSPlugin) Load(id string) (string, error) {
	// TODO: integrate with Oracle Cloud KMS.
	return "oracle-kms-" + id, nil
}

func init() { Register(oracleKMSPlugin{}) }
