package plugins

import (
	"context"

	"github.com/winhowes/AuthTranslator/app/secrets"
)

// winCredPlugin loads generic credentials from Windows Credential Manager.
// id should be the credential TargetName.
type winCredPlugin struct{}

func (winCredPlugin) Prefix() string { return "wincred" }

func (winCredPlugin) Load(ctx context.Context, id string) (string, error) {
	return loadWindowsCredential(id)
}

func init() { secrets.Register(winCredPlugin{}) }
