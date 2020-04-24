package models

import "github.com/louisevanderlith/husk"

type User struct {
	Name     string `hsk:"size(75)"`
	Verified bool   `hsk:"default(false)"`
	Email    string `hsk:"size(128)"`
	Password string `hsk:"min(6)"`
	Contact  Contact
}

func (u User) Valid() (bool, error) {
	return husk.ValidateStruct(&u)
}

func (u User) VerifyPassword(password string) bool {
	return u.Password == password
}