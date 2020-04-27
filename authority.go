package kong

import (
	"crypto/rsa"
	"errors"
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
}

func (a Authority) Authorize(clientId, username, password string, claims ...string) (tokens.UserToken, error) {
	idparts := strings.Split(clientId, ".")

	if len(idparts) != 2 {
		return tokens.UserToken{}, errors.New("id is invalid")
	}

	prof, err := a.Profiles.GetProfile(idparts[0])

	if err != nil {
		return tokens.UserToken{}, err
	}

	_, err = prof.GetClient(idparts[1])

	if err != nil {
		return tokens.UserToken{}, err
	}

	id, usr := a.Users.GetUserByName(username)

	if !usr.VerifyPassword(password) {
		return tokens.UserToken{}, errors.New("invalid user")
	}

	return tokens.UserToken{
		Name:   usr.GetName(),
		Key:    id,
		Claims: claims,
	}, nil
}

//RequestToken will return an Encoded token on success
//id: clientId
//secret: clientSecret
//ut: pre-authenticated user token
//scopes: resources used by the requesting page.
func (a Authority) RequestToken(id, secret string, ut tokens.UserToken, resources ...string) ([]byte, error) {
	idparts := strings.Split(id, ".")

	if len(idparts) != 2 {
		return nil, errors.New("id is invalid")
	}

	prof, err := a.Profiles.GetProfile(idparts[0])

	if err != nil {
		return nil, err
	}

	clnt, err := prof.GetClient(idparts[1])

	if err != nil {
		return nil, err
	}

	if clnt.Secret != secret {
		return nil, errors.New("client unauthorized")
	}

	fullClaims := make(tokens.Claims)
	fullClaims.AddClaim("kong.client", clnt.Name)
	fullClaims.AddClaim("kong.iat", time.Now().String())
	fullClaims.AddClaim("kong.exp", time.Now().Add(time.Minute*5).String())

	usr := a.Users.GetUser(ut.Key)

	for _, rsrc := range resources {
		if !clnt.ResourceAllowed(rsrc) {
			return nil, errors.New("scope not allowed")
		}

		resrc, err := a.Resources.GetResource(rsrc)

		if err != nil {
			return nil, err
		}

		vals, err := resrc.AssignNeeds(prof, ut.Key, usr)

		if err != nil {
			return nil, err
		}

		fullClaims.AddClaims(vals)
	}

	return fullClaims.Encode(&a.SignCert.PublicKey)
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

	return resrc.ExtractNeeds(accs)
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
