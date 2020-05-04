package fakes

import (
	"github.com/louisevanderlith/kong/prime"
	"github.com/louisevanderlith/kong/tokens"
)

type fakeResourceStore struct {
	Resources []prime.Resource
}

func NewFakeResources() []prime.Resource {
	return []prime.Resource{
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
}
