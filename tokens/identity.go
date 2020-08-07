package tokens

import (
	"errors"
	"fmt"
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
	servIdx := strings.Index(name, ".")
	url, ok := ends[name[:servIdx]]

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

	codes := codesClms.(map[string]interface{})
	code, ok := codes[name]

	if !ok {
		return "", fmt.Errorf("code %s not found in %v", name, codes)
	}

	return code.(string), nil
}

func (c *identity) GetTerm(name string) (string, error) {
	termsClms := c.GetClaim(KongTerms)

	if termsClms == nil {
		return "", errors.New("kong.terms claim not found")
	}

	terms := termsClms.(map[string]interface{})
	term, ok := terms[name]

	if !ok {
		return "", fmt.Errorf("terms %s not found in %v", name, terms)
	}

	return term.(string), nil
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
