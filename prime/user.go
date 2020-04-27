package prime

import "github.com/louisevanderlith/husk"

type User struct {
	Name     string `hsk:"size(75)"`
	Verified bool   `hsk:"default(false)"`
	Email    string `hsk:"size(128)"`
	Password string `hsk:"min(6)"`
	Contacts Contacts
}

func (u User) Valid() (bool, error) {
	return husk.ValidateStruct(&u)
}

func (u User) VerifyPassword(password string) bool {
	return u.Password == password
}

func (u User) ProvideClaim(claim string) string {
	result := ""

	switch claim {
	case "name":
		result = u.Name
	case "email":
		result = u.Email
	default:
		result = u.Contacts.ProvideClaim(claim)
	}

	return result
}
