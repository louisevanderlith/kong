package kong

import (
	"fmt"
)

type Claimer interface {
	AddClaim(key, val string) error
	GetClaims() map[string]string
}

func NewClaimer() Claimer {
	return &claimr{
		claims: make(map[string]string),
	}
}

type claimr struct {
	scopes []string
	claims map[string]string
}

func (c *claimr) AddClaim(key, val string) error {
	//empty values are simply skipped
	if len(val) == 0 {
		return nil
	}

	if v, ok := c.claims[key]; ok {
		return fmt.Errorf("%s has already been assigned with %s", key, v)
	}

	c.claims[key] = val

	return nil
}

func (c *claimr) GetClaims() map[string]string {
	return c.claims
}