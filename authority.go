package kong

import (
	"crypto/rsa"
	"errors"
	"fmt"
	"github.com/gorilla/sessions"
	"github.com/louisevanderlith/kong/prime"
	"github.com/louisevanderlith/kong/stores"
	"github.com/louisevanderlith/kong/tokens"
	"strings"
	"time"
)

type Author interface {
	RequestToken(id, secret string, ut tokens.Claimer, resources ...string) (tokens.Claimer, error)
	Inspect(token, resource, secret string) (tokens.Claimer, error)
	Info(token, secret string) (tokens.Claimer, error)                   //local api
	Login(id, username, password string) (tokens.Claimer, error)         //partial token
	Consent(ut tokens.Claimer, claims ...string) (tokens.Claimer, error) //finalize token
	Sign(token tokens.Claimer) (string, error)
	GetCallback(token tokens.Claimer) (string, error)
}

type authority struct {
	Store    stores.AuthStore
	SignCert *rsa.PrivateKey
	Cookies  sessions.Store
}

func CreateAuthority(store stores.AuthStore, certpath string, sessstore sessions.Store) (Author, error) {
	signr, err := InitializeCert(certpath, len(certpath) > 0)

	if err != nil {
		return nil, err
	}

	return authority{
		Store:    store,
		SignCert: signr,
		Cookies:  sessstore,
	}, nil
}

//Signs the claims
func (a authority) Sign(token tokens.Claimer) (string, error) {
	return token.Encode(&a.SignCert.PublicKey)
}

//GetCallback returns
func (a authority) GetCallback(token tokens.Claimer) (string, error) {
	if !token.IsExpired() {
		return "", errors.New("token expired")
	}

	prof, clnt, err := a.getProfileClient(token)

	if err != nil {
		return "", err
	}

	sgnd, err := a.Sign(token)

	if err != nil {
		return "", err
	}

	return fmt.Sprintf("https://%s.%s/callback?user=%s", strings.ToLower(clnt.Name), prof.Domain, sgnd), nil
}

//Login returns the Client's User Key Token after successful authentication
func (a authority) Login(id, username, password string) (tokens.Claimer, error) {
	result, err := tokens.StartClaims(id)

	if err != nil {
		return nil, err
	}

	usrClaims, err := a.loginUser(username, password)

	if err != nil {
		return nil, err
	}

	result.AddClaims(usrClaims)
	result.AddClaim(tokens.KongIssued, time.Now().Format("2006-01-02T15:04:05"))
	result.AddClaim(tokens.KongExpired, time.Now().Add(time.Minute*5).Format("2006-01-02T15:04:05"))

	return result, nil
}

//loginUser returns the User's Key Token after successful authentication
func (a authority) loginUser(username, password string) (tokens.Claimer, error) {
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

//Consent applies the claim values of allowed scopes, and finalises login
func (a authority) Consent(ut tokens.Claimer, claims ...string) (tokens.Claimer, error) {
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
func (a authority) RequestToken(id, secret string, ut tokens.Claimer, resources ...string) (tokens.Claimer, error) {
	result, err := tokens.StartClaims(id)

	if err != nil {
		return nil, err
	}

	prof, clnt, err := a.getProfileClient(result)

	if err != nil {
		return nil, err
	}

	if !clnt.VerifySecret(secret) {
		return nil, errors.New("client unauthorized")
	}

	result.AddClaim(tokens.KongIssued, time.Now().Format("2006-01-02T15:04:05"))
	result.AddClaim(tokens.KongExpired, time.Now().Add(time.Minute*5).Format("2006-01-02T15:04:05"))

	//Get Client needs from Profile
	result.AddClaims(clnt.ExtractNeeds(prof))

	k, _ := ut.GetUserinfo()
	usr := a.Store.GetUser(k)

	for _, rsrc := range resources {
		if !clnt.ResourceAllowed(rsrc) {
			return nil, errors.New("scope not allowed")
		}

		resrc, err := a.Store.GetResource(rsrc)

		if err != nil {
			return nil, err
		}

		if usr != nil && !usr.ResourceAllowed(rsrc) {
			return nil, errors.New("scope not allowed")
		}

		vals, err := resrc.AssignNeeds(prof, k, usr)

		if err != nil {
			return nil, err
		}

		result.AddClaims(vals)
	}

	return result, nil
}

//Info returns token information to the client
func (a authority) Info(token, secret string) (tokens.Claimer, error) {
	clms, err := tokens.OpenClaims(token, a.SignCert)

	if err != nil {
		return nil, err
	}

	_, clnt, err := a.getProfileClient(clms)

	if err != nil {
		return nil, err
	}

	if !clnt.VerifySecret(secret) {
		return nil, errors.New("invalid client")
	}

	return clms, nil
}

//Inspect returns the resources requested token information to the resource
func (a authority) Inspect(token, resource, secret string) (tokens.Claimer, error) {
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

func (a authority) getProfileClient(clms tokens.Claimer) (prime.Profile, prime.Client, error) {
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

/*
//Barrel returns claims that are currently rolling
func (a Authority) Barrel(r *http.Request) (tokens.Claimer, error) {
	session, err := a.Cookies.Get(r, "sess-store")
	if err != nil {
		return nil, err
	}

	res, ok := session.Values["user.id"]

	if !ok {
		return nil, errors.New("no barrel")
	}

	return res.(tokens.Claimer), nil
}


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
