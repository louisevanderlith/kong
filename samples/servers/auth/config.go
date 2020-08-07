package auth

import (
	"github.com/gorilla/securecookie"
	"github.com/gorilla/sessions"
	"github.com/louisevanderlith/kong"
	"net/http"
)

var (
	SessionStore sessions.Store
	Authority     kong.Authority
)

func SetupAuthServer(clnt *http.Client, securityUrl, managerUrl, token string) {
	stor := sessions.NewCookieStore(
		securecookie.GenerateRandomKey(64),
		securecookie.GenerateRandomKey(32),
	)

	stor.Options.Secure = true
	stor.Options.HttpOnly = true

	SessionStore = stor
	Authority = kong.NewAuthority(clnt, securityUrl, managerUrl, token)
}
