package kong

import (
	"crypto/rand"
	"errors"
	"github.com/louisevanderlith/kong/prime"
	"github.com/louisevanderlith/kong/stores"
	"github.com/louisevanderlith/kong/tokens"
	"io"
	"time"
)

type Author interface {
	RequestToken(id, secret, ut string, resources ...string) (tokens.Claimer, error)
	Inspect(token, resource, secret string) (tokens.Claimer, error)
	Info(token, secret string) (tokens.Claimer, error)           //local api
	Login(id, username, password string) (tokens.Claimer, error) //partial token
	Consent(ut string, claims ...string) (tokens.Claimer, error) //finalize token
	Sign(token tokens.Claimer) (string, error)
	QueryClient(partial string) (prime.ClientQuery, error)
	GetStore() stores.AuthStore
}

type authority struct {
	Store stores.AuthStore
	Users stores.UserStore
	key   []byte //must be 32byte
}

func CreateAuthority(store stores.AuthStore, users stores.UserStore) (Author, error) {
	return authority{
		Store: store,
		Users: users,
		key:   generateKey(32),
	}, nil
}

func generateKey(len int) []byte {
	k := make([]byte, len)
	if _, err := io.ReadFull(rand.Reader, k); err != nil {
		return nil
	}

	return k
}

func (a authority) GetStore() stores.AuthStore {
	return a.Store
}

//Signs the claims
func (a authority) Sign(claims tokens.Claimer) (string, error) {
	return EncodeClaims(a.key, claims)
}

func (a authority) openClaims(token string) (tokens.Claimer, error) {
	result, err := DecodeToken(a.key, token)

	if err != nil {
		return nil, err
	}

	return result, nil
}

func (a authority) QueryClient(partial string) (prime.ClientQuery, error) {
	clms, err := a.openClaims(partial)

	if err != nil {
		return prime.ClientQuery{}, err
	}

	if !clms.HasUser() {
		return prime.ClientQuery{}, errors.New("no user found in token")
	}

	if clms.IsExpired() {
		return prime.ClientQuery{}, errors.New("partial token expired")
	}

	_, username := clms.GetUserinfo()
	_, clnt, err := a.Store.GetProfileClient(clms.GetId())

	if err != nil {
		return prime.ClientQuery{}, err
	}

	result := prime.ClientQuery{
		Username: username,
		Consent:  make(map[string][]string),
	}

	for _, v := range clnt.AllowedResources {
		rsrc, err := a.Store.GetResource(v)

		if err != nil {
			return prime.ClientQuery{}, err
		}

		var concern []string

		for _, n := range rsrc.Needs {
			concern = append(concern, n)
		}

		result.Consent[rsrc.DisplayName] = concern
	}

	return result, nil
}

//GetCallback returns
/*
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
}*/

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

	return result, nil
}

//loginUser returns the User's Key Token after successful authentication
func (a authority) loginUser(username, password string) (tokens.Claimer, error) {
	id, usr := a.Users.GetUserByName(username)

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
func (a authority) Consent(usrtkn string, claims ...string) (tokens.Claimer, error) {
	if len(claims) == 0 {
		return nil, errors.New("no consented claims")
	}

	ut, err := a.openClaims(usrtkn)

	if err != nil {
		return nil, err
	}

	for _, v := range claims {
		ut.AddClaim(v, "")
	}

	ut.AddClaim(tokens.KongIssued, time.Now())
	ut.AddClaim(tokens.KongExpired, time.Now().Add(time.Minute*5))

	return ut, nil
}

//RequestToken will return an Encoded token on success
//id: clientId
//secret: clientSecret
//ut: pre-authenticated user token
//scopes: resources used by the requesting page.
func (a authority) RequestToken(id, secret, usrtkn string, resources ...string) (tokens.Claimer, error) {
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

	result.AddClaim(tokens.KongIssued, time.Now())
	result.AddClaim(tokens.KongExpired, time.Now().Add(time.Minute*5))

	//Get Client needs from Profile
	result.AddClaims(clnt.ExtractNeeds(prof))

	usr, ut, err := a.getUserToken(usrtkn)

	if err != nil {
		return nil, err
	}

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

		vals, err := resrc.AssignNeeds(ut)

		if err != nil {
			return nil, err
		}

		result.AddClaims(vals)
	}

	return result, nil
}

func (a authority) getUserToken(usrtkn string) (prime.Userer, tokens.Claimer, error) {
	if len(usrtkn) == 0 {
		return nil, nil, nil
	}

	ut, err := a.openClaims(usrtkn)

	if err != nil {
		return nil, nil, err
	}

	if ut.IsExpired() {
		return nil, nil, errors.New("token expired")
	}

	k, _ := ut.GetUserinfo()
	usr := a.Users.GetUser(k)

	return usr, ut, nil
}

//Info returns token information to the client
func (a authority) Info(token, secret string) (tokens.Claimer, error) {
	clms, err := a.openClaims(token)

	if err != nil {
		return nil, err
	}

	if clms.IsExpired() {
		return nil, errors.New("token expired")
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

	clms, err := a.openClaims(token)

	if err != nil {
		return nil, err
	}

	if clms.IsExpired() {
		return nil, errors.New("token expired")
	}

	return resrc.ExtractNeeds(clms)
}

func (a authority) Whitelist(resource, secret string) ([]string, error) {
	resrc, err := a.Store.GetResource(resource)

	if err != nil {
		return nil, err
	}

	if !resrc.VerifySecret(secret) {
		return nil, errors.New("invalid secret")
	}

	return a.Store.GetWhitelist(), nil
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
