package tests

import "kong/models"

type fakeUserStore struct {
	Users map[string]models.User
}

func newFakeUS() fakeUserStore {
	usrs := map[string]models.User{
		"00": {
			Name:     "user1",
			Verified: true,
			Email:    "user@fake.com",
			Password: "user1pass",
			Contact:  models.Contact{},
		},
	}

	return fakeUserStore{usrs}
}

func (us fakeUserStore) GetUser(id string) models.User {
	return us.Users[id]
}

func (us fakeUserStore) GetUserByName(username string) (string, models.User) {
	for k, v := range us.Users {
		if v.Email == username {
			return k, v
		}
	}

	return "", models.User{}
}
