package plugins

import (
	_ "github.com/winhowes/AuthTranslator/app/auth/plugins/aws_imds"
	_ "github.com/winhowes/AuthTranslator/app/auth/plugins/azure_managed_identity"
	_ "github.com/winhowes/AuthTranslator/app/auth/plugins/basic"
	_ "github.com/winhowes/AuthTranslator/app/auth/plugins/findreplace"
	_ "github.com/winhowes/AuthTranslator/app/auth/plugins/gcp_token"
	_ "github.com/winhowes/AuthTranslator/app/auth/plugins/github_signature"
	_ "github.com/winhowes/AuthTranslator/app/auth/plugins/google_oidc"
	_ "github.com/winhowes/AuthTranslator/app/auth/plugins/hmac"
	_ "github.com/winhowes/AuthTranslator/app/auth/plugins/jwt"
	_ "github.com/winhowes/AuthTranslator/app/auth/plugins/mtls"
	_ "github.com/winhowes/AuthTranslator/app/auth/plugins/passthrough"
	_ "github.com/winhowes/AuthTranslator/app/auth/plugins/slack_signature"
	_ "github.com/winhowes/AuthTranslator/app/auth/plugins/token"
	_ "github.com/winhowes/AuthTranslator/app/auth/plugins/twilio_signature"
	_ "github.com/winhowes/AuthTranslator/app/auth/plugins/urlpath"
)
