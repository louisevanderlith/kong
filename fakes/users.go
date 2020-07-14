package fakes

import (
	"github.com/louisevanderlith/kong/prime"
	"github.com/louisevanderlith/kong/stores"
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

func NewFakeUserStore() stores.UserStore {
	return userStore{
		Users: NewFakeUsers(),
	}
}

type userStore struct {
	Users map[string]prime.Userer
}

func (s userStore) GetUser(id string) prime.Userer {
	return s.Users[id]
}

func (s userStore) GetUserByName(username string) (string, prime.Userer) {
	for k, v := range s.Users {
		if v.GetEmail() == username {
			return k, v
		}
	}

	return "", nil
}
