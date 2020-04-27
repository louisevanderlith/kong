package fakes

import "github.com/louisevanderlith/kong/prime"

type fakeUserStore struct {
	Users map[string]prime.User
}

func NewFakeUS() fakeUserStore {
	usrs := map[string]prime.User{
		"00": {
			Name:     "user1",
			Verified: true,
			Email:    "user@fake.com",
			Password: "user1pass",
			Contacts:  []prime.Contact{},
		},
	}

	return fakeUserStore{usrs}
}

func (us fakeUserStore) GetUser(id string) prime.User {
	return us.Users[id]
}

func (us fakeUserStore) GetUserByName(username string) (string, prime.User) {
	for k, v := range us.Users {
		if v.Email == username {
			return k, v
		}
	}

	return "", prime.User{}
}
