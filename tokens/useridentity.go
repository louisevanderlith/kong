package tokens

import (
	"errors"
	"github.com/louisevanderlith/kong/prime/roletype"
)

type UserIdentity interface {
	Claims
	GetUserID() string
	GetDisplayName() string
	GetAudience() string
	GetRole() roletype.Enum
	GiveConsent() error
}

//Common claims
const (
	UserKey      = "user.key"
	UserName     = "user.name"
	UserAudience = "user.aud"
	UserRole     = "user.role"
	UserConsent  = "user.consent"
)

type userIdentity = claims

func EmptyUserIdentity() UserIdentity {
	return &userIdentity{make(map[string]interface{})}
}

func NewUserIdentity(k, name, audience string) UserIdentity {
	result := &userIdentity{make(map[string]interface{})}

	result.AddClaim(UserKey, k)
	result.AddClaim(UserName, name)
	result.AddClaim(UserAudience, audience)

	return result
}

func OpenUserIdentity(key []byte, token string) (UserIdentity, error) {
	result := &userIdentity{}
	err := DecodeToken(key, token, result)

	if err != nil {
		return nil, err
	}

	return result, nil
}

func (c *userIdentity) GetDisplayName() string {
	return c.GetClaimString(UserName)
}

func (c *userIdentity) GetUserID() string {
	return c.GetClaimString(UserKey)
}

func (c *userIdentity) GetAudience() string {
	return c.GetClaimString(UserAudience)
}

func (c *userIdentity) GetRole() roletype.Enum {
	return c.GetClaim(UserRole).(roletype.Enum)
}

func (c *userIdentity) GiveConsent() error {
	if c.HasClaim(UserConsent) {
		return errors.New("consent already applied")
	}

	return errors.New("nothing")
}
