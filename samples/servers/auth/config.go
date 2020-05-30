package auth

import (
	"github.com/gorilla/securecookie"
	"github.com/gorilla/sessions"
	"github.com/louisevanderlith/kong"
	"net/http"
)

var (
	SessionStore sessions.Store
	Security     kong.Securer
)

func SetupAuthServer(clnt *http.Client, authURL, tokn string) {
	stor := sessions.NewCookieStore(
		securecookie.GenerateRandomKey(64),
		securecookie.GenerateRandomKey(32),
	)

	stor.Options.Secure = true
	stor.Options.HttpOnly = true

	SessionStore = stor
	Security = kong.NewSecurity(clnt, authURL, tokn)
}
