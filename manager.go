package kong

import (
	"errors"
	"fmt"
	"github.com/louisevanderlith/kong/prime"
	"github.com/louisevanderlith/kong/stores"
	"github.com/louisevanderlith/kong/tokens"
	"log"
	"time"
)

//Manager controls User authentication
type Manager interface {
	tokens.Signer
	UserInsider
	Login(id, username, password string) (tokens.UserIdentity, error)              //partial token
	Consent(usrToken string, consent map[string]bool) (tokens.UserIdentity, error) //finalize token
	FetchNeeds(usrToken string, needs ...string) (tokens.UserIdentity, error)
}

func NewManager(users stores.UserStore) Manager {
	return manager{key: tokens.GenerateKey(32), users: users}
}

type manager struct {
	key   []byte
	users stores.UserStore
}

//Insight for Clients and Resources, they've already proved they can open an identity.
func (m manager) Insight(request prime.QueryRequest) (tokens.Claims, error) {
	clms, err := tokens.OpenUserIdentity(m.key, request.Token)

	if err != nil {
		return nil, err
	}

	if clms.IsExpired() {
		return nil, errors.New("token expired")
	}

	return clms, nil
}

//Login returns the Client's User Key Token after successful authentication
func (m manager) Login(audience, username, password string) (tokens.UserIdentity, error) {
	id, usr := m.users.GetUserByName(username)

	if usr == nil {
		return nil, errors.New("invalid user")
	}

	if !usr.VerifyPassword(password) {
		return nil, errors.New("invalid user")
	}

	result := tokens.NewUserIdentity(id, usr.GetName(), audience)

	return result, nil
}

//Consent applies the claim values of allowed scopes, and finalises login
func (m manager) Consent(usrToken string, consent map[string]bool) (tokens.UserIdentity, error) {
	idn, err := tokens.OpenUserIdentity(m.key, usrToken)

	if err != nil {
		return nil, err
	}

	usr := m.users.GetUser(idn.GetUserID())

	if usr == nil {
		return nil, fmt.Errorf("unable to find user %s", idn.GetDisplayName())
	}

	for clm, accept := range consent {
		if accept {
			v, err := usr.ProvideClaim(clm)

			if err != nil {
				//just log, don't break
				log.Println("Provide Consent Claim", err)
			}

			idn.AddClaim(clm, v)
		}
	}

	return idn, nil
}

func (m manager) FetchNeeds(usrToken string, needs ...string) (tokens.UserIdentity, error) {
	idn, err := tokens.OpenUserIdentity(m.key, usrToken)

	if err != nil {
		return nil, err
	}

	result := tokens.NewUserIdentity(idn.GetUserID(), idn.GetDisplayName(), idn.GetAudience())

	for _, n := range needs {
		val := idn.GetClaim(n)
		result.AddClaim(n, val)
	}

	return result, nil
}

func (m manager) Sign(claims tokens.Claims, exp time.Duration) (string, error) {
	return tokens.IssueClaims(m.key, claims, exp)
}
