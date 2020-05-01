package fakes

import "github.com/louisevanderlith/kong/prime"

type fakeUserStore struct {
	Users map[string]prime.Userer
}

func NewFakeUS() fakeUserStore {
	usrs := map[string]prime.Userer{
		"00": prime.NewUser("User 1", "user@fake.com", "user1pass", true, []prime.Contact{}),
	}

	return fakeUserStore{usrs}
}

func (us fakeUserStore) GetUser(id string) prime.Userer {
	return us.Users[id]
}

func (us fakeUserStore) GetUserByName(username string) (string, prime.Userer) {
	for k, v := range us.Users {
		if v.GetEmail() == username {
			return k, v
		}
	}

	return "", nil
}
