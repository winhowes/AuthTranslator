package plugins

import (
	_ "github.com/winhowes/AuthTranslator/app/secrets/plugins/aws"
	_ "github.com/winhowes/AuthTranslator/app/secrets/plugins/azure"
	_ "github.com/winhowes/AuthTranslator/app/secrets/plugins/env"
	_ "github.com/winhowes/AuthTranslator/app/secrets/plugins/file"
	_ "github.com/winhowes/AuthTranslator/app/secrets/plugins/gcp"
	_ "github.com/winhowes/AuthTranslator/app/secrets/plugins/k8s"
	_ "github.com/winhowes/AuthTranslator/app/secrets/plugins/vault"
)
