package kong

import (
	"errors"
	"fmt"
	"github.com/louisevanderlith/kong/prime"
	"github.com/louisevanderlith/kong/stores"
	"github.com/louisevanderlith/kong/tokens"
	"strings"
	"time"
)

//Security controls Client and Resource authentication
type Security interface {
	tokens.Signer
	IdentityInsider
	RequestToken(id, secret, ut string, resources map[string]bool) (tokens.Identity, error)
	QueryClient(partial string) (prime.ClientQuery, error)
	Whitelist(resource, secret string) ([]string, error)
}

type security struct {
	Store stores.SecureStore
	key   []byte //must be 32byte
}

func CreateSecurity(store stores.SecureStore) (Security, error) {
	return security{
		Store: store,
		key:   tokens.GenerateKey(32),
	}, nil
}

//Signs the claims
func (s security) Sign(claims tokens.Claims, exp time.Duration) (string, error) {
	return tokens.IssueClaims(s.key, claims, exp)
}

func (s security) QueryClient(partial string) (prime.ClientQuery, error) {
	idn, err := tokens.OpenIdentity(s.key, partial)

	if err != nil {
		return prime.ClientQuery{}, err
	}

	if !idn.HasUser() {
		return prime.ClientQuery{}, errors.New("no user found in token")
	}

	if idn.IsExpired() {
		return prime.ClientQuery{}, errors.New("partial token expired")
	}

	_, clnt, err := s.Store.GetProfileClient(idn.GetID())

	if err != nil {
		return prime.ClientQuery{}, err
	}

	result := prime.ClientQuery{
		Username: "nobody",
		Consent:  make(map[string][]string),
	}

	for _, v := range clnt.AllowedResources {
		rsrc, err := s.Store.GetResource(v)

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

//RequestToken will return an Encoded token on success
//id: clientId
//secret: clientSecret
//ut: pre-authenticated user token
//scopes: resources used by the requesting page. TRUE == REQUIRED
func (s security) RequestToken(id, secret, usrtkn string, resources map[string]bool) (tokens.Identity, error) {
	result, err := tokens.NewIdentity(id)

	if err != nil {
		return nil, err
	}

	prof, clnt, err := s.Store.GetProfileClient(result.GetID())

	if err != nil {
		return nil, err
	}

	if !clnt.VerifySecret(secret) {
		return nil, errors.New("client unauthorized")
	}

	//Get Client needs from Profile
	result.AddClaims(prof.GetClientClaims(clnt))

	for rsrc, must := range resources {
		if !clnt.ResourceAllowed(rsrc) {
			msg := "scope not allowed"

			if must {
				msg = "required " + msg
			}

			return nil, errors.New(msg)
		}

		resrc, err := s.Store.GetResource(rsrc)

		if err != nil {
			return nil, err
		}

		if len(resrc.Needs) > 0 && len(usrtkn) == 0 {
			return nil, errors.New("invalid user token")
		}
	}

	if len(usrtkn) > 0 {
		result.AddClaim(tokens.KongUser, usrtkn)
	}

	return result, nil
}

//ClientInsight returns token information to the client
func (s security) ClientInsight(token, secret string) (tokens.Identity, error) {
	clms, err := tokens.OpenIdentity(s.key, token)

	if err != nil {
		return nil, err
	}

	if clms.IsExpired() {
		return nil, errors.New("token expired")
	}

	_, clnt, err := s.Store.GetProfileClient(clms.GetID())

	if err != nil {
		return nil, err
	}

	if !clnt.VerifySecret(secret) {
		return nil, errors.New("invalid client")
	}

	return clms, nil
}

//ResourceInsight returns the resources requested token information to the resource
func (s security) ResourceInsight(token, resource, secret string) (tokens.Identity, error) {
	resrc, err := s.Store.GetResource(resource)

	if err != nil {
		return nil, err
	}

	if !resrc.VerifySecret(secret) {
		return nil, errors.New("invalid secret")
	}

	clms, err := tokens.OpenIdentity(s.key, token)

	if err != nil {
		return nil, err
	}

	if clms.IsExpired() {
		return nil, errors.New("token expired")
	}

	_, err = clms.GetResourceURL(resource)

	if err != nil {
		return nil, fmt.Errorf("token doesn't allow resource %s", resource)
	}

	return clms, nil
}

func (s security) Whitelist(resource, secret string) ([]string, error) {
	resrc, err := s.Store.GetResource(resource)

	if err != nil {
		return nil, err
	}

	if !resrc.VerifySecret(secret) {
		return nil, errors.New("invalid secret")
	}

	dotIdx := strings.Index(resrc.Name, ".")
	return s.Store.GetWhitelist(resrc.Name[:dotIdx]), nil
}
