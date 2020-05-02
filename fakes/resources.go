package fakes

import (
	"fmt"
	"github.com/louisevanderlith/kong/prime"
	"github.com/louisevanderlith/kong/tokens"
)

type fakeResourceStore struct {
	Resources []prime.Resource
}

func NewFakeRS() fakeResourceStore {
	rsrc := []prime.Resource{
		{
			Name:        "api.profile.view",
			DisplayName: "Displays the profile's information",
			Secret:      "secret",
			Needs:       []string{tokens.KongProfile, tokens.KongClient},
		},
		{
			Name:        "api.user.view",
			DisplayName: "Displays the user's information",
			Secret:      "secret",
			Needs:       []string{tokens.KongProfile, tokens.KongClient, tokens.UserName, tokens.UserKey},
		},
	}
	return fakeResourceStore{rsrc}
}

func (s fakeResourceStore) GetResource(name string) (prime.Resource, error) {
	for _, v := range s.Resources {
		if v.Name == name {
			return v, nil
		}
	}

	return prime.Resource{}, fmt.Errorf("scope %s not found", name)
}
