package tokens

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha512"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
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

func (c Claims) getObject(claim string) map[string]string {
	val := c.GetClaimString(claim)
	res := make(map[string]string)
	err := json.Unmarshal([]byte(val), &res)

	if err != nil {
		log.Println(err)
		return nil
	}

	return res
}

func (c Claims) GetResourceURL(name string) (string, error) {
	ends := c.getObject(KongEndpoints)
	url, ok := ends[name]

	if !ok {
		return "", fmt.Errorf("endpoint %s not found in %v", name, ends)
	}

	return url, nil
}

func (c Claims) GetCode(name string) (string, error) {
	codes := c.getObject(KongCodes)
	url, ok := codes[name]

	if !ok {
		return "", fmt.Errorf("code %s not found in %v", name, codes)
	}

	return url, nil
}

func (c Claims) GetTerm(name string) (string, error) {
	terms := c.getObject(KongTerms)
	url, ok := terms[name]

	if !ok {
		return "", fmt.Errorf("terms %s not found in %v", name, terms)
	}

	return url, nil
}
