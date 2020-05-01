package kong

import (
	"crypto/rsa"
	"errors"
	"github.com/gorilla/sessions"
	"github.com/louisevanderlith/kong/prime"
	"github.com/louisevanderlith/kong/signing"
	"github.com/louisevanderlith/kong/stores"
	"github.com/louisevanderlith/kong/tokens"
	"strings"
	"time"
)

type Authority struct {
	Profiles  stores.ProfileStore
	Users     stores.UserStore
	Resources stores.ResourceStore
	SignCert  *rsa.PrivateKey
	Cookies   sessions.Store
}

func (a Authority) Authorize(clientId, username, password string) (tokens.Claimer, error) {
	prof, clnt, err := a.GetProfileClient(clientId)

	if err != nil {
		return nil, err
	}

	id, usr := a.Users.GetUserByName(username)

	if usr == nil {
		return nil, errors.New("invalid user")
	}

	if !usr.VerifyPassword(password) {
		return nil, errors.New("invalid user")
	}

	result := make(tokens.Claims)
	result.AddClaim("kong.id", clientId)
	result.AddClaim("kong.profile", prof.Title)
	result.AddClaim("kong.client", clnt.Name)
	result.AddClaim("kong.iat", time.Now().Format("2006-01-02T15:04:05"))
	result.AddClaim("kong.exp", time.Now().Add(time.Minute*5).Format("2006-01-02T15:04:05"))
	result.AddClaim("user.name", usr.GetName())
	result.AddClaim("user.key", id)

	return result, nil
}

func (a Authority) Consent(ut tokens.Claimer, claims ...string) (tokens.Claimer, error) {
	if len(claims) == 0 {
		return nil, errors.New("no consented claims")
	}

	//ut.Claims = claims
	return ut, nil
}

//RequestToken will return an Encoded token on success
//id: clientId
//secret: clientSecret
//ut: pre-authenticated user token
//scopes: resources used by the requesting page.
func (a Authority) RequestToken(id, secret string, ut tokens.Claimer, resources ...string) (string, error) {
	prof, clnt, err := a.GetProfileClient(id)

	if err != nil {
		return "", err
	}

	if clnt.Secret != secret {
		return "", errors.New("client unauthorized")
	}

	fullClaims := make(tokens.Claims)
	fullClaims.AddClaim("kong.id", id)
	fullClaims.AddClaim("kong.profile", prof.Title)
	fullClaims.AddClaim("kong.client", clnt.Name)
	fullClaims.AddClaim("kong.iat", time.Now().Format("2006-01-02T15:04:05"))
	fullClaims.AddClaim("kong.exp", time.Now().Add(time.Minute*5).Format("2006-01-02T15:04:05"))

	_, k := ut.GetUserinfo()
	usr := a.Users.GetUser(k)

	for _, rsrc := range resources {
		if !clnt.ResourceAllowed(rsrc) {
			return "", errors.New("scope not allowed")
		}

		resrc, err := a.Resources.GetResource(rsrc)

		if err != nil {
			return "", err
		}

		vals, err := resrc.AssignNeeds(prof, k, usr)

		if err != nil {
			return "", err
		}

		fullClaims.AddClaims(vals)
	}

	return fullClaims.Encode(&a.SignCert.PublicKey)
}

func (a Authority) Info(token, clientId, secret string) (tokens.Claimer, error) {
	_, clnt, err := a.GetProfileClient(clientId)

	if err != nil {
		return nil, err
	}

	if !clnt.VerifySecret(secret) {
		return nil, errors.New("invalid secret")
	}

	accs, err := signing.DecodeToken(token, a.SignCert)

	if err != nil {
		return nil, err
	}

	if accs.IsExpired() {
		return nil, errors.New("token expired")
	}

	clms := accs.GetKong()

	if accs.HasUser() {
		nme := "user.name"
		clms.AddClaim(nme, accs.GetClaim(nme))
	}

	clms.AddClaim("kong.client", accs.GetClient())

	return clms, nil
}

func (a Authority) Inspect(token, resource, secret string) (tokens.Claimer, error) {
	resrc, err := a.Resources.GetResource(resource)

	if err != nil {
		return nil, err
	}

	if !resrc.VerifySecret(secret) {
		return nil, errors.New("invalid secret")
	}

	accs, err := signing.DecodeToken(token, a.SignCert)

	if err != nil {
		return nil, err
	}

	if accs.IsExpired() {
		return nil, errors.New("token expired")
	}

	return resrc.ExtractNeeds(accs)
}

func (a Authority) GetProfileClient(id string) (prime.Profile, prime.Client, error) {
	idparts := strings.Split(id, ".")

	if len(idparts) != 2 {
		return prime.Profile{}, prime.Client{}, errors.New("id is invalid")
	}

	prof, err := a.Profiles.GetProfile(idparts[0])

	if err != nil {
		return prime.Profile{}, prime.Client{}, err
	}

	clnt, err := prof.GetClient(idparts[1])

	if err != nil {
		return prime.Profile{}, prime.Client{}, err
	}

	return prof, clnt, nil
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
