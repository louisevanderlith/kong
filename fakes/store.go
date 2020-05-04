package fakes

import (
	"errors"
	"fmt"
	"github.com/louisevanderlith/kong/prime"
	"github.com/louisevanderlith/kong/stores"
	"strings"
)

type fakeStore struct {
	Profiles  []prime.Profile
	Resources []prime.Resource
	Users     map[string]prime.Userer
}

func NewFakeStore() stores.AuthStore {
	return fakeStore{
		Profiles:  NewFakeProfiles(),
		Resources: NewFakeResources(),
		Users:     NewFakeUsers(),
	}
}

func (s fakeStore) GetProfile(id string) (prime.Profile, error) {
	for _, v := range s.Profiles {
		if strings.ToLower(v.Title) == id {
			return v, nil
		}
	}

	return prime.Profile{}, errors.New("profile not found")
}

func (s fakeStore) GetUser(id string) prime.Userer {
	return s.Users[id]
}

func (s fakeStore) GetUserByName(username string) (string, prime.Userer) {
	for k, v := range s.Users {
		if v.GetEmail() == username {
			return k, v
		}
	}

	return "", nil
}

func (s fakeStore) GetResource(name string) (prime.Resource, error) {
	for _, v := range s.Resources {
		if v.Name == name {
			return v, nil
		}
	}

	return prime.Resource{}, fmt.Errorf("scope %s not found", name)
}
