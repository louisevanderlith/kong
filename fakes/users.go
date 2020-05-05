package fakes

import (
	"github.com/louisevanderlith/kong/prime"
	"golang.org/x/crypto/bcrypt"
)

func NewFakeUsers() map[string]prime.Userer {
	pss, err := bcrypt.GenerateFromPassword([]byte("user1pass"), 11)
	if err != nil {
		panic(err)
	}

	return map[string]prime.Userer{
		"00": prime.NewUser("User 1", "user@fake.com", pss, true, []prime.Contact{}),
	}
}
