package fakes

import (
	"errors"
	"fmt"
	"github.com/louisevanderlith/kong/prime"
	"github.com/louisevanderlith/kong/stores"
	"strings"
)

func NewFakeStore() stores.AuthStore {
	return fakeStore{
		Profiles:  NewFakeProfiles(),
		Resources: NewFakeResources(),
	}
}

type fakeStore struct {
	Profiles  []prime.Profile
	Resources []prime.Resource
}

func (s fakeStore) GetWhitelist() []string {
	var result []string

	for _, v := range s.Profiles {
		for _, c := range v.Clients {
			result = append(result, c.Url)
		}
	}

	return result
}

func (s fakeStore) GetProfile(id string) (prime.Profile, error) {
	if len(id) == 0 {
		return prime.Profile{}, errors.New("id is empty")
	}
	for _, v := range s.Profiles {
		if strings.ToLower(v.Title) == id {
			return v, nil
		}
	}

	return prime.Profile{}, fmt.Errorf("profile '%s' not found", id)
}

func (s fakeStore) GetResource(name string) (prime.Resource, error) {
	for _, v := range s.Resources {
		if v.Name == name {
			return v, nil
		}
	}

	return prime.Resource{}, fmt.Errorf("scope %s not found", name)
}

func (s fakeStore) GetProfileClient(id string) (prime.Profile, prime.Client, error) {
	idparts := strings.Split(id, ".")

	if len(idparts) != 2 {
		return prime.Profile{}, prime.Client{}, errors.New("id is invalid")
	}

	prof, err := s.GetProfile(idparts[0])

	if err != nil {
		return prime.Profile{}, prime.Client{}, err
	}

	clnt, err := prof.GetClient(idparts[1])

	if err != nil {
		return prime.Profile{}, prime.Client{}, err
	}

	return prof, clnt, nil
}
