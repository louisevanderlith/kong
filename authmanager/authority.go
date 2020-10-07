package authmanager

import (
	"github.com/gorilla/securecookie"
	"github.com/gorilla/sessions"
	"github.com/louisevanderlith/kong/core"
	"github.com/louisevanderlith/kong/prime"
	"github.com/louisevanderlith/kong/stores"
)

var (
	_sessionStore sessions.Store
	_authority    core.AuthorityManager
)

func InitializeManager(svc stores.AuthorityService, secure bool) {
	stor := sessions.NewCookieStore(
		securecookie.GenerateRandomKey(64),
		securecookie.GenerateRandomKey(32),
	)

	stor.Options.Secure = secure
	stor.Options.HttpOnly = true

	_sessionStore = stor
	_authority = newAuthority(svc)
}

type authority struct {
	svc stores.AuthorityService
}

//NewAuthority returns a client which can call the Secure & Entity server's API
func newAuthority(scv stores.AuthorityService) core.AuthorityManager {
	return authority{scv}
}

//ClientQuery returns the username and the client's required claims
func (a authority) ClientQuery(client string) (prime.ClaimConsent, error) {
	tknreq := prime.TokenRequest{
		UserToken: "",
		Scopes:    map[string]bool{"secure.client.query": true},
	}

	tknresp, err := a.svc.RequestToken(tknreq)

	if err != nil {
		return prime.ClaimConsent{}, err
	}

	return a.svc.QueryClient(client, tknresp.Token)
}

//GiveConsent returns a signed user token
func (a authority) GiveConsent(request prime.QueryRequest) (string, error) {
	tknreq := prime.TokenRequest{
		UserToken: "",
		Scopes:    map[string]bool{"entity.consent.apply": true},
	}

	tknresp, err := a.svc.RequestToken(tknreq)

	if err != nil {
		return "", err
	}

	return a.svc.ApplyConsent(request, tknresp.Token)
}

//AuthenticateUser returns a signed partial user token
func (a authority) AuthenticateUser(request prime.LoginRequest) (string, error) {
	tknreq := prime.TokenRequest{
		UserToken: "",
		Scopes:    map[string]bool{"entity.login.apply": true},
	}
	tknresp, err := a.svc.RequestToken(tknreq)

	if err != nil {
		return "", err
	}

	return a.svc.AuthenticateUser(request, tknresp.Token)
}
