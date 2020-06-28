package tokens

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha512"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

type Claimer interface {
	GetKong() Claimer
	GetProfile() string
	GetClient() string
	GetId() string
	HasUser() bool
	GetUserinfo() (string, string) //key, username
	IsExpired() bool
	AddClaim(key string, val interface{}) error
	AddClaims(more Claimer) error
	HasClaim(name string) bool
	GetClaim(name string) interface{}
	GetClaimString(name string) string
	GetAll() map[string]interface{}
	GetResourceURL(name string) (string, error)
	GetCode(name string) (string, error)
	GetTerm(name string) (string, error)
}

//Common claims
const (
	KongID        = "kong.id"
	KongClient    = "kong.client"
	KongProfile   = "kong.profile"
	KongTerms     = "kong.terms"
	KongCodes     = "kong.codes"
	KongEndpoints = "kong.endpoints"
	KongLogo      = "kong.logo"
	KongIssued    = "kong.iat"
	KongExpired   = "kong.exp"
	UserKey       = "user.key"
	UserName      = "user.name"
)

type Claims map[string]interface{}

func StartClaims(id string) (Claimer, error) {
	result := make(Claims)
	idparts := strings.Split(id, ".")

	if len(idparts) != 2 {
		return nil, errors.New("id is invalid")
	}

	result.AddClaim(KongID, id)
	result.AddClaim(KongProfile, idparts[0])
	result.AddClaim(KongClient, idparts[1])

	return result, nil
}

func OpenClaims(raw string, prvKey *rsa.PrivateKey) (Claimer, error) {
	tkn, err := hex.DecodeString(raw)

	if err != nil {
		return nil, err
	}

	dcryptd, err := rsa.DecryptOAEP(sha512.New(), rand.Reader, prvKey, tkn, []byte("access"))

	if err != nil {
		return nil, err
	}

	result := make(Claims)
	err = json.Unmarshal(dcryptd, &result)

	if err != nil {
		return nil, err
	}

	if result.IsExpired() {
		return nil, errors.New("token expired")
	}

	return result, nil
}

func (c Claims) GetClient() string {
	return c.GetClaimString(KongClient)
}

func (c Claims) HasUser() bool {
	return c.HasClaim(UserKey)
}

func (c Claims) GetUserinfo() (string, string) {
	return c.GetClaimString(UserKey), c.GetClaimString(UserName)
}

func (c Claims) IsExpired() bool {
	val, ok := c[KongExpired]

	if !ok {
		return true
	}

	exp, err := time.Parse("2006-01-02T15:04:05.000000000Z07:00", val.(string))

	if err != nil {
		return true
	}

	return time.Now().After(exp)
}

func (c Claims) GetAll() map[string]interface{} {
	return c
}

func (c Claims) HasClaim(name string) bool {
	_, ok := c[name]

	return ok
}

func (c Claims) GetClaim(name string) interface{} {
	return c[name]
}

func (c Claims) GetClaimString(name string) string {
	if !c.HasClaim(name) {
		return ""
	}

	return c[name].(string)
}

func (c Claims) AddClaim(key string, val interface{}) error {
	//empty values are simply skipped
	if val == nil {
		return nil
	}

	if v, ok := c[key]; ok {
		return fmt.Errorf("%s has already been assigned with %s", key, v)
	}

	c[key] = val

	return nil
}

func (c Claims) AddClaims(more Claimer) error {
	for k, v := range more.GetAll() {
		if v != nil {
			err := c.AddClaim(k, v)

			if err != nil {
				return err
			}
		}
	}

	return nil
}

func (c Claims) GetId() string {
	return c.GetClaimString(KongID)
}

func (c Claims) GetProfile() string {
	return c.GetClaimString(KongProfile)
}

func (c Claims) GetKong() Claimer {
	result := make(Claims)

	for k, v := range c {
		if strings.HasPrefix(k, "kong.") {
			result[k] = v
		}
	}

	return result
}

func (c Claims) GetResourceURL(name string) (string, error) {
	endsClms := c.GetClaim(KongEndpoints)

	if endsClms == nil {
		return "", errors.New("kong.endpoints claim not found")
	}

	ends := endsClms.(map[string]interface{})
	url, ok := ends[name]

	if !ok {
		return "", fmt.Errorf("endpoint %s not found in %v", name, ends)
	}

	return url.(string), nil
}

func (c Claims) GetCode(name string) (string, error) {
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

func (c Claims) GetTerm(name string) (string, error) {
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
