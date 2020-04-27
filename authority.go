package kong

import (
	"crypto/rsa"
	"errors"
	"fmt"
	"github.com/louisevanderlith/kong/inspectors"
	"github.com/louisevanderlith/kong/prime"
	"github.com/louisevanderlith/kong/stores"
	"github.com/louisevanderlith/kong/tokens"
	"strings"
)

type Authority struct {
	Profiles  stores.ProfileStore
	Users     stores.UserStore
	Resources stores.ResourceStore
	SignCert  *rsa.PrivateKey
}

func (a Authority) Authorize(clientId, username, password string, claims ...string) (tokens.UserToken, error) {
	id, usr := a.Users.GetUserByName(username)

	if !usr.VerifyPassword(password) {
		return tokens.UserToken{}, errors.New("invalid user")
	}

	return tokens.UserToken{
		Name:   usr.Name,
		Key:    id,
		Claims: claims,
	}, nil
}

func (a Authority) RequestToken(id, secret string, ut tokens.UserToken, scope string) ([]byte, error) {
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

	if !clnt.HasScope(scope) {
		return nil, errors.New("scope not allowed")
	}

	fullclaims, err := a.populateClaims(scope, prof, ut)

	if err != nil {
		return nil, err
	}

	tkn := tokens.AccessToken{
		Client:     clnt.Name,
		FullClaims: fullclaims,
	}

	return tkn.Encode(&a.SignCert.PublicKey)
}

func (a Authority) Spill(token string) (map[string]string, error) {
	ins := inspectors.NewLazyInspector(a.SignCert)
	return ins.Exchange(token, "", "")
}

func (a Authority) Inspect(token, scope, secret string) (map[string]string, error) {
	ins := inspectors.NewLocalInspector(a.SignCert, a.Resources)
	return ins.Exchange(token, scope, secret)
}

func (a Authority) populateClaims(scope string, prof prime.Profile, ut tokens.UserToken) (map[string]string, error) {
	clms := NewClaimer()

	resrc, err := a.Resources.GetResource(scope)

	if err != nil {
		return nil, err
	}

	//Requires a user scope?
	var usr prime.User

	if strings.HasPrefix(scope, "user") {
		if ut.Key == "" {
			return nil, errors.New("invalid user token")
		}

		usr = a.Users.GetUser(ut.Key)
	}

	for _, v := range resrc.Claims {
		//Profile Claims
		err := clms.AddClaim(v, prof.ProvideClaim(v))

		if err != nil {
			return nil, err
		}

		//User Claims
		if ut.Key != "" {
			err = clms.AddClaim(v, usr.ProvideClaim(v))

			if err != nil {
				return nil, err
			}
		}
	}

	result := make(map[string]string)

	for k, v := range clms.GetClaims() {
		fullclaim := fmt.Sprintf("%s.%s", scope, k)
		result[fullclaim] = v
	}

	return result, nil
}
