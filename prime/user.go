package prime

import (
	"errors"
	"github.com/louisevanderlith/husk"
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
	Password  []byte `hsk:"min(6)"`
	Contacts  Contacts
	Resources []string
}

func NewUser(name, email string, password []byte, verified bool, contacts Contacts, resources []string) Userer {
	return User{
		Name:      name,
		Email:     email,
		Password:  password,
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

func (u User) Valid() (bool, error) {
	return husk.ValidateStruct(&u)
}

func (u User) VerifyPassword(password string) bool {
	err := bcrypt.CompareHashAndPassword(u.Password, []byte(password))
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

	return "", errors.New("no claim found")
}

func (u User) ResourceAllowed(name string) bool {
	for _, v := range u.Resources {
		if v == name {
			return true
		}
	}
	return false
}
