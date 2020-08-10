package tokens

import (
	"errors"
)

type UserIdentity interface {
	Claims
	GetUserID() string
	GetDisplayName() string
	GiveConsent() error
}

//Common claims
const (
	UserKey     = "user.key"
	UserName    = "user.name"
	UserConsent = "user.consent"
)

type userIdentity = claims

func EmptyUserIdentity() UserIdentity {
	return &userIdentity{make(map[string]interface{})}
}

func NewUserIdentity(k, name string) UserIdentity {
	result := &userIdentity{make(map[string]interface{})}

	result.AddClaim(UserKey, k)
	result.AddClaim(UserName, name)

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

func (c *userIdentity) GiveConsent() error {
	if c.HasClaim(UserConsent) {
		return errors.New("consent already applied")
	}

	return errors.New("nothing")
}
