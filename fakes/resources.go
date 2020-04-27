package fakes

import (
	"fmt"
	"github.com/louisevanderlith/kong/prime"
)

type fakeResourceStore struct {
	Resources []prime.Resource
}

func NewFakeRS() fakeResourceStore {
	rsrc := []prime.Resource{
		{
			Name:        "theme.assets.download",
			DisplayName: "Download Theme assets",
			Secret:      "secret",
			Needs:       []string{"profile.name"},
		},
		{
			Name:        "theme.assets.view",
			DisplayName: "View Theme assets",
			Secret:      "secret",
			Needs:       []string{"profile.name"},
		},
		{
			Name:        "artifact.download",
			DisplayName: "Download Artifacts",
			Secret:      "secret",
			Needs:       nil,
		},
		{
			Name:        "api.view.profile",
			DisplayName: "Displays the profile's information",
			Secret:      "secret",
			Needs:       []string{"profile.name"},
		},
		{
			Name:        "api.view.user",
			DisplayName: "Displays the user's information",
			Secret:      "secret",
			Needs:       []string{"user.name", "user.key"},
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
