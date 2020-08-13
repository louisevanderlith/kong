package tokens

import (
	"errors"
	"fmt"
	"github.com/louisevanderlith/kong/dict"
	"strings"
)

type Identity interface {
	Claims

	GetID() string
	GetProfile() string
	GetClient() string
	GetLogo() string

	HasUser() bool
	GetUserToken() string
	GetResourceURL(name string) (string, error)
	GetCode(name string) (string, error)
	GetTerm(name string) (string, error)
}

func EmptyIdentity() Identity {
	return &identity{make(map[string]interface{})}
}

func NewIdentity(id string) (Identity, error) {
	result := &identity{make(map[string]interface{})}
	idparts := strings.Split(id, ".")

	if len(idparts) != 2 {
		return nil, errors.New("id is invalid")
	}

	result.AddClaim(KongID, id)
	result.AddClaim(KongProfile, idparts[0])
	result.AddClaim(KongClient, idparts[1])

	return result, nil
}

func OpenIdentity(key []byte, token string) (Identity, error) {
	result := &identity{}
	err := DecodeToken(key, token, result)

	if err != nil {
		return nil, err
	}

	return result, nil
}

//Common claims
const (
	KongID        = "kong.id"
	KongProfile   = "kong.profile"
	KongClient    = "kong.client"
	KongLogo      = "kong.logo"
	KongTerms     = "kong.terms"
	KongCodes     = "kong.codes"
	KongEndpoints = "kong.endpoints"
	KongContacts  = "kong.contacts"
	KongUser      = "kong.user"
)

type identity = userIdentity

func (c *identity) GetResourceURL(name string) (string, error) {
	endsClms := c.GetClaim(KongEndpoints)

	if endsClms == nil {
		return "", errors.New("kong.endpoints claim not found")
	}

	ends := endsClms.(map[string]interface{})

	if strings.Contains(name, ".") {
		servIdx := strings.Index(name, ".")
		name = name[:servIdx]
	}

	url, ok := ends[name]

	if !ok {
		return "", fmt.Errorf("endpoint %s not found in %v", name, ends)
	}

	return url.(string), nil
}

func (c *identity) HasUser() bool {
	return c.HasClaim(KongUser)
}

func (c *identity) GetUserToken() string {
	return c.GetClaimString(KongUser)
}

func (c *identity) GetCode(name string) (string, error) {
	codesClms := c.GetClaim(KongCodes)

	if codesClms == nil {
		return "", errors.New("kong.codes claim not found")
	}

	codes, isMap := codesClms.(dict.Map)

	if isMap {
		return codes.Get(name), nil
	}

	if pairs, isSlice := codesClms.([]interface{}); isSlice {
		for i := 0; i < len(pairs); i++ {
			kv := pairs[i].(map[string]interface{})

			if kv["Key"] == name {
				return kv["Value"].(string), nil
			}
		}
	}

	return "", fmt.Errorf("code %s not found in %v", name, codes)
}

func (c *identity) GetTerm(name string) (string, error) {
	termsClms := c.GetClaim(KongTerms)

	if termsClms == nil {
		return "", errors.New("kong.terms claim not found")
	}

	terms, isMap := termsClms.(dict.Map)

	if isMap {
		return terms.Get(name), nil
	}

	if pairs, isSlice := termsClms.([]interface{}); isSlice {
		for i := 0; i < len(pairs); i++ {
			kv := pairs[i].(map[string]interface{})

			if kv["Key"] == name {
				return kv["Value"].(string), nil
			}
		}
	}

		return "", fmt.Errorf("terms %s not found in %v", name, terms)
}

func (c *identity) GetID() string {
	return c.GetClaimString(KongID)
}

func (c *identity) GetProfile() string {
	return c.GetClaimString(KongProfile)
}

func (c *identity) GetClient() string {
	return c.GetClaimString(KongClient)
}

func (c *identity) GetLogo() string {
	return c.GetClaimString(KongLogo)
}
