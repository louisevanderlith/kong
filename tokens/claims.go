package tokens

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha512"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"strings"
	"time"
)

type Claimer interface {
	GetKong() Claimer
	GetClient() string
	GetId() string
	HasUser() bool
	GetUserinfo() (string, string) //key, username
	IsExpired() bool
	AddClaim(key, val string) error
	AddClaims(more Claimer) error
	HasClaim(name string) bool
	GetClaim(name string) string
	GetAll() map[string]string
	Encode(pubkey *rsa.PublicKey) (string, error)
}

type Claims map[string]string

func (c Claims) GetClient() string {
	return c["kong.client"]
}

func (c Claims) HasUser() bool {
	return c.HasClaim("user.key")
}

func (c Claims) GetUserinfo() (string, string) {
	return c.GetClaim("user.key"), c.GetClaim("user.name")
}

func (c Claims) IsExpired() bool {
	val, ok := c["kong.exp"]

	if !ok {
		return true
	}

	exp, err := time.Parse("2006-01-02T15:04:05", val)

	if err != nil {
		log.Println(err)
		return true
	}

	return time.Now().After(exp)
}

func (c Claims) GetAll() map[string]string {
	return c
}

func (c Claims) HasClaim(name string) bool {
	_, ok := c[name]

	return ok
}

func (c Claims) GetClaim(name string) string {
	return c[name]
}

func (c Claims) AddClaim(key, val string) error {
	//empty values are simply skipped
	if len(val) == 0 {
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
		if len(v) > 0 {
			err := c.AddClaim(k, v)

			if err != nil {
				return err
			}
		}
	}

	return nil
}

func (c Claims) Encode(pubkey *rsa.PublicKey) (string, error) {
	bits, err := json.Marshal(c)

	if err != nil {
		return "", err
	}

	ciphertxt, err := rsa.EncryptOAEP(sha512.New(), rand.Reader, pubkey, bits, []byte("access"))

	if err != nil {
		return "", err
	}

	val := hex.EncodeToString(ciphertxt)

	return val, nil
}

func (c Claims) GetId() string {
	return c["kong.id"]
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
