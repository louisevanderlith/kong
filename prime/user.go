package prime

import (
	"errors"
	"github.com/louisevanderlith/husk"
)

type User interface {
	GetName() string
	GetEmail() string
	IsVerified() bool
	VerifyPassword(password string) bool
	ProvideClaim(claim string) (string, error)
}

type user struct {
	Name     string `hsk:"size(75)"`
	Verified bool   `hsk:"default(false)"`
	Email    string `hsk:"size(128)"`
	Password string `hsk:"min(6)"`
	Contacts Contacts
}

func NewUser(name, email, password string, verified bool, contacts Contacts) User {
	return user{
		Name: name,
		Email: email,
		Password: password,
		Verified: verified,
		Contacts: contacts,
	}
}

func (u user) GetName() string {
	return u.Name
}

func (u user) GetEmail() string {
	return u.Email
}

func (u user) IsVerified() bool {
	return u.Verified
}

func (u user) Valid() (bool, error) {
	return husk.ValidateStruct(&u)
}

func (u user) VerifyPassword(password string) bool {
	return u.Password == password
}

func (u user) ProvideClaim(claim string) (string, error) {
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
