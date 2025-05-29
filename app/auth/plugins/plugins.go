package plugins

import (
	_ "github.com/winhowes/AuthTranslator/app/auth/plugins/basic"
	_ "github.com/winhowes/AuthTranslator/app/auth/plugins/github_signature"
	_ "github.com/winhowes/AuthTranslator/app/auth/plugins/google_oidc"
	_ "github.com/winhowes/AuthTranslator/app/auth/plugins/hmac"
	_ "github.com/winhowes/AuthTranslator/app/auth/plugins/jwt"
	_ "github.com/winhowes/AuthTranslator/app/auth/plugins/mtls"
	_ "github.com/winhowes/AuthTranslator/app/auth/plugins/passthrough"
	_ "github.com/winhowes/AuthTranslator/app/auth/plugins/slack_signature"
	_ "github.com/winhowes/AuthTranslator/app/auth/plugins/token"
	_ "github.com/winhowes/AuthTranslator/app/auth/plugins/urlpath"
)
