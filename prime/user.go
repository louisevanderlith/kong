package prime

import (
	"fmt"
	"github.com/louisevanderlith/husk/validation"
	"github.com/louisevanderlith/kong/prime/roletype"
	"golang.org/x/crypto/bcrypt"
)

type Userer interface {
	GetName() string
	GetEmail() string
	IsVerified() bool
	VerifyPassword(password string) bool
	ResourceAllowed(name string) bool
	ProvideClaim(claim string) (string, error)
}

type User struct {
	Name      string `hsk:"size(75)"`
	Verified  bool   `hsk:"default(false)"`
	Email     string `hsk:"size(128)"`
	Password  string `hsk:"min(6)"`
	Contacts  Contacts
	Resources []string
	Roles     []Role
}

func NewUser(name, email, password string, verified bool, contacts Contacts, resources []string) Userer {
	pss, err := bcrypt.GenerateFromPassword([]byte(password), 11)
	if err != nil {
		panic(err)
	}

	return User{
		Name:      name,
		Email:     email,
		Password:  string(pss),
		Verified:  verified,
		Contacts:  contacts,
		Resources: resources,
	}
}

func (u User) GetName() string {
	return u.Name
}

func (u User) GetEmail() string {
	return u.Email
}

func (u User) IsVerified() bool {
	return u.Verified
}

func (u User) Valid() error {
	return validation.Struct(u)
}

func (u User) VerifyPassword(password string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(u.Password), []byte(password))
	return err == nil
}

func (u User) ProvideClaim(claim string) (string, error) {
	switch claim {
	case "name":
		return u.Name, nil
	case "email":
		return u.Email, nil
	default:
		return u.Contacts.ProvideClaim(claim)
	}

	return "", fmt.Errorf("user: no '%s' claim found", claim)
}

func (u User) ClientRole(profileID string) roletype.Enum {
	if len(profileID) == 0 {
		return roletype.Nobody
	}

	for _, v := range u.Roles {
		if v.ProfileID == profileID {
			return v.Role
		}
	}

	return roletype.Nobody
}

func (u User) ResourceAllowed(name string) bool {
	for _, v := range u.Resources {
		if v == name {
			return true
		}
	}

	return false
}
