package plugins

import (
	_ "github.com/winhowes/AuthTranslator/app/authplugins/basic"
	_ "github.com/winhowes/AuthTranslator/app/authplugins/github_signature"
	_ "github.com/winhowes/AuthTranslator/app/authplugins/google_oidc"
	_ "github.com/winhowes/AuthTranslator/app/authplugins/hmac"
	_ "github.com/winhowes/AuthTranslator/app/authplugins/jwt"
	_ "github.com/winhowes/AuthTranslator/app/authplugins/mtls"
	_ "github.com/winhowes/AuthTranslator/app/authplugins/slack_signature"
	_ "github.com/winhowes/AuthTranslator/app/authplugins/token"
	_ "github.com/winhowes/AuthTranslator/app/authplugins/urlpath"
)
