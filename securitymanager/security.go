package securitymanager

import (
	"errors"
	"fmt"
	"github.com/louisevanderlith/kong/core"
	"github.com/louisevanderlith/kong/prime"
	"github.com/louisevanderlith/kong/stores"
	"github.com/louisevanderlith/kong/tokens"
	"strings"
	"time"
)

var _security core.SecurityManager

//InitializeManager will assign the store to a new security manager
func InitializeManager(store stores.SecureStore) {
	s, err := createSecurity(store)

	if err != nil {
		panic(err)
	}

	_security = s
}

type security struct {
	Store stores.SecureStore
	key   []byte //must be 32byte
}

func createSecurity(store stores.SecureStore) (core.SecurityManager, error) {
	return security{
		Store: store,
		key:   tokens.GenerateKey(32),
	}, nil
}

//Signs the claims
func (s security) Sign(claims tokens.Claims, exp time.Duration) (string, error) {
	return tokens.IssueClaims(s.key, claims, exp)
}

func (s security) ClientResourceQuery(clientId string) (prime.ClaimConsent, error) {
	_, clnt, err := s.Store.GetProfileClient(clientId)

	if err != nil {
		return prime.ClaimConsent{}, err
	}

	result := prime.ClaimConsent{
		Client: clnt.Name,
		Needs:  make(map[string][]string),
	}

	for _, v := range clnt.AllowedResources {
		rsrc, err := s.Store.GetResource(v)

		if err != nil {
			return prime.ClaimConsent{}, err
		}

		for _, n := range rsrc.Needs {
			result.Needs[n] = append(result.Needs[n], rsrc.DisplayName)
		}
	}

	return result, nil
}

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
			msg := fmt.Sprintf("scope %s not allowed", rsrc)

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
