package prime

import (
	"errors"
	"github.com/louisevanderlith/husk"
)

type Userer interface {
	GetName() string
	GetEmail() string
	IsVerified() bool
	VerifyPassword(password string) bool
	ProvideClaim(claim string) (string, error)
}

type User struct {
	Name     string `hsk:"size(75)"`
	Verified bool   `hsk:"default(false)"`
	Email    string `hsk:"size(128)"`
	Password string `hsk:"min(6)"`
	Contacts Contacts
}

func NewUser(name, email, password string, verified bool, contacts Contacts) Userer {
	return User{
		Name:     name,
		Email:    email,
		Password: password,
		Verified: verified,
		Contacts: contacts,
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
	return u.Password == password
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
