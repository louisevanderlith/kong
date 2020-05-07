package kong

import (
	"crypto/rsa"
	"errors"
	"github.com/gorilla/sessions"
	"github.com/louisevanderlith/kong/prime"
	"github.com/louisevanderlith/kong/stores"
	"github.com/louisevanderlith/kong/tokens"
	"net/http"
	"time"
)

type Authority struct {
	Store    stores.AuthStore
	SignCert *rsa.PrivateKey
	Cookies  sessions.Store
}

func CreateAuthority(store stores.AuthStore, certpath string, sessstore sessions.Store) Authority {
	signr, err := InitializeCert(certpath, len(certpath) > 0)

	if err != nil {
		panic(err)
	}

	return Authority{
		Store:    store,
		SignCert: signr,
		Cookies:  sessstore,
	}
}

//AuthenticateUser returns the User's Key after successful authentication
func (a Authority) AuthenticateUser(username, password string) (tokens.Claimer, error) {
	id, usr := a.Store.GetUserByName(username)

	if usr == nil {
		return nil, errors.New("invalid user")
	}

	if !usr.VerifyPassword(password) {
		return nil, errors.New("invalid user")
	}

	result := make(tokens.Claims)

	result.AddClaim(tokens.UserName, usr.GetName())
	result.AddClaim(tokens.UserKey, id)

	return result, nil
}

func (a Authority) Authorize(id, username, password string) (tokens.Claimer, error) {
	result, err := tokens.StartClaims(id)

	if err != nil {
		return nil, err
	}

	id, usr := a.Store.GetUserByName(username)

	if usr == nil {
		return nil, errors.New("invalid user")
	}

	if !usr.VerifyPassword(password) {
		return nil, errors.New("invalid user")
	}

	result.AddClaim(tokens.KongIssued, time.Now().Format("2006-01-02T15:04:05"))
	result.AddClaim(tokens.KongExpired, time.Now().Add(time.Minute*5).Format("2006-01-02T15:04:05"))
	result.AddClaim(tokens.UserName, usr.GetName())
	result.AddClaim(tokens.UserKey, id)

	return result, nil
}

func (a Authority) Consent(ut tokens.Claimer, claims ...string) (tokens.Claimer, error) {
	if len(claims) == 0 {
		return nil, errors.New("no consented claims")
	}

	return ut, nil
}

//RequestToken will return an Encoded token on success
//id: clientId
//secret: clientSecret
//ut: pre-authenticated user token
//scopes: resources used by the requesting page.
func (a Authority) RequestToken(id, secret string, ut tokens.Claimer, resources ...string) (string, error) {
	result, err := tokens.StartClaims(id)

	if err != nil {
		return "", err
	}

	prof, clnt, err := a.GetProfileClient(result)

	if err != nil {
		return "", err
	}

	if !clnt.VerifySecret(secret) {
		return "", errors.New("client unauthorized")
	}

	result.AddClaim(tokens.KongIssued, time.Now().Format("2006-01-02T15:04:05"))
	result.AddClaim(tokens.KongExpired, time.Now().Add(time.Minute*5).Format("2006-01-02T15:04:05"))

	//Get Client needs from Profile
	result.AddClaims(clnt.ExtractNeeds(prof))

	k, _ := ut.GetUserinfo()
	usr := a.Store.GetUser(k)

	for _, rsrc := range resources {
		if !clnt.ResourceAllowed(rsrc) {
			return "", errors.New("scope not allowed")
		}

		resrc, err := a.Store.GetResource(rsrc)

		if err != nil {
			return "", err
		}

		if usr != nil && !usr.ResourceAllowed(rsrc) {
			return "", errors.New("scope not allowed")
		}

		vals, err := resrc.AssignNeeds(prof, k, usr)

		if err != nil {
			return "", err
		}

		result.AddClaims(vals)
	}

	return result.Encode(&a.SignCert.PublicKey)
}

func (a Authority) Info(token, secret string) (tokens.Claimer, error) {
	clms, err := tokens.OpenClaims(token, a.SignCert)

	if err != nil {
		return nil, err
	}

	_, clnt, err := a.GetProfileClient(clms)

	if err != nil {
		return nil, err
	}

	if !clnt.VerifySecret(secret) {
		return nil, errors.New("invalid client")
	}

	return clms, nil
}

func (a Authority) Inspect(token, resource, secret string) (tokens.Claimer, error) {
	resrc, err := a.Store.GetResource(resource)

	if err != nil {
		return nil, err
	}

	if !resrc.VerifySecret(secret) {
		return nil, errors.New("invalid secret")
	}

	clms, err := tokens.OpenClaims(token, a.SignCert)

	if err != nil {
		return nil, err
	}

	return resrc.ExtractNeeds(clms)
}

func (a Authority) GetProfileClient(clms tokens.Claimer) (prime.Profile, prime.Client, error) {
	prof, err := a.Store.GetProfile(clms.GetProfile())

	if err != nil {
		return prime.Profile{}, prime.Client{}, err
	}

	clnt, err := prof.GetClient(clms.GetClient())

	if err != nil {
		return prime.Profile{}, prime.Client{}, err
	}

	return prof, clnt, nil
}

//Barrel returns claims that are currently rolling
func (a Authority) Barrel(r *http.Request) (tokens.Claimer, error) {
	session, err := a.Cookies.Get(r, "sess-store")
	if err != nil {
		return nil, err
	}

	res, ok := session.Values["barrel"]

	if !ok {
		return nil, errors.New("no barrel")
	}

	return res.(tokens.Claimer), nil
}

/*
func (a Authority) populateClaims(resource string, prof prime.Profile, ut tokens.UserToken) (string, error) {
	resrc, err := a.Resources.GetResource(resource)

	if err != nil {
		return "", err
	}

	for k, v := range clms.GetClaims() {
		fullclaim := fmt.Sprintf("%s.%s", resource, k)
		clmer.AddClaim(fullclaim, v)
	}

	return "", errors.New("nothing happened")
}
*/
