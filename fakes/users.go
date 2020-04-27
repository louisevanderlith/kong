package fakes

import "github.com/louisevanderlith/kong/prime"

type fakeUserStore struct {
	Users map[string]prime.User
}

func NewFakeUS() fakeUserStore {
	usrs := map[string]prime.User{
		"00": prime.NewUser("user1", "user@fake.com", "user1pass", true, []prime.Contact{}),
	}

	return fakeUserStore{usrs}
}

func (us fakeUserStore) GetUser(id string) prime.User {
	return us.Users[id]
}

func (us fakeUserStore) GetUserByName(username string) (string, prime.User) {
	for k, v := range us.Users {
		if v.GetEmail() == username {
			return k, v
		}
	}

	return "", nil
}
