package fakes

import (
	"github.com/louisevanderlith/kong/prime"
)

func NewFakeUsers() map[string]prime.Userer {
	return map[string]prime.Userer{
		"00": prime.NewUser("User 1", "user@fake.com", "user1pass", true, []prime.Contact{{
			Icon:  "fa-facebook",
			Name:  "facebook",
			Value: "http://facebook.com/user1",
		}}, []string{
			"api.user.view",
			"api.profile.view",
		}),
	}
}
