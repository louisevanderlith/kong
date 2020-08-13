package tokens

import (
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

//Claims holds key-value pairs
type Claims interface {
	AddClaim(key string, val interface{}) error
	AddClaims(more Claims) error

	HasClaim(name string) bool
	GetClaim(name string) interface{}
	GetClaimString(name string) string

	ToMap() map[string]interface{}

	IsExpired() bool
	IssuedAt() (time.Time, error)
	ExpiresAt() (time.Time, error)
}

const (
	KongIssued  = "kong.iat"
	KongExpired = "kong.exp"
)

//EmptyClaims returns a new instance of a Claims dict
func EmptyClaims() Claims {
	return &claims{make(map[string]interface{})}
}

type claims struct {
	values map[string]interface{}
}

func (c *claims) AddUserIdentity(idn UserIdentity) error {
	if idn.IsExpired() {
		return errors.New("user identity expired")
	}

	return c.AddClaim(KongUser, idn)
}

func (c *claims) IsExpired() bool {
	exp, err := c.ExpiresAt()

	if err != nil {
		return true
	}

	return time.Now().After(exp)
}

func (c *claims) IssuedAt() (time.Time, error) {
	val, ok := c.values[KongIssued]

	if !ok {
		return time.Time{}, errors.New("'issued at' not in token")
	}

	return time.Parse(time.RFC3339Nano, val.(string))
}

func (c *claims) ExpiresAt() (time.Time, error) {
	val, ok := c.values[KongExpired]

	if !ok {
		return time.Time{}, errors.New("'expires at' not in token")
	}

	return time.Parse(time.RFC3339Nano, val.(string))
}

func (c *claims) ToMap() map[string]interface{} {
	return c.values
}

func (c *claims) HasClaim(name string) bool {
	_, ok := c.values[name]

	return ok
}

func (c *claims) GetClaim(name string) interface{} {
	return c.values[name]
}

func (c *claims) GetClaimString(name string) string {
	if !c.HasClaim(name) {
		return ""
	}

	return c.values[name].(string)
}

func (c *claims) AddClaim(key string, val interface{}) error {
	if val == nil {
		return errors.New("val is empty")
	}

	if v, ok := c.values[key]; ok {
		return fmt.Errorf("%s has already been assigned with %s", key, v)
	}

	c.values[key] = val

	return nil
}

func (c *claims) AddClaims(more Claims) error {
	for k, v := range more.ToMap() {
		if v != nil {
			err := c.AddClaim(k, v)

			if err != nil {
				return err
			}
		}
	}

	return nil
}

func (c *claims) MarshalJSON() ([]byte, error) {
	return json.Marshal(c.values)
}

func (c *claims) UnmarshalJSON(b []byte) error {
	return json.Unmarshal(b, &c.values)
}
