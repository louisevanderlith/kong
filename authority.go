package kong

import (
	"errors"
	"kong/models"
	"kong/stores"
	"strings"
)

type Authority struct {
	Profiles stores.ProfileStore
	Users    stores.UserStore
	Scopes   stores.ScopeStore
}

func (a Authority) Authorize(clientId, username, password string, scopes ...string) (UserToken, error) {
	id, usr := a.Users.GetUserByName(username)

	if !usr.VerifyPassword(password) {
		return UserToken{}, errors.New("invalid user")
	}

	return UserToken{
		Name:   usr.Name,
		Key:    id,
		Scopes: scopes,
	}, nil
}

func (a Authority) RequestToken(id, secret string, ut UserToken, scope string) (Accessor, error) {
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

	scopes, claims, err := a.populateClaims(scope, prof, ut)

	if err != nil {
		return nil, err
	}

	return AccessToken{
		Client: clnt.Name,
		Scopes: scopes,
		Claims: claims,
	}, nil
}

func (a Authority) populateClaims(scope string, prof models.Profile, ut UserToken) ([]string, map[string]string, error) {
	clms := NewClaimer()

	scp, err := a.Scopes.GetScope(scope)

	if err != nil {
		return nil, nil, err
	}

	//Requires a user scope?
	if strings.Contains(scope, "user") {
		if ut.Key == "" {
			return nil, nil, errors.New("invalid user token")
		}

		if scope == "user.info" {
			for _, v := range scp.GetClaims() {
				//User Claims
				err := clms.AddClaim(v, ut.GetClaim(v))

				if err != nil {
					return nil, nil, err
				}
			}
		}
	}

	for _, v := range scp.GetClaims() {
		//Profile Claims
		err := clms.AddClaim(v, prof.GetClaim(v))

		if err != nil {
			return nil, nil, err
		}
	}

	return []string{scope}, clms.GetClaims(), nil
}
