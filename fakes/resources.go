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
		{
			Name:        "kong.consent.apply",
			DisplayName: "Allows applications to update consent",
			Secret:      "secret",
			Needs:       []string{tokens.KongProfile, tokens.KongClient},
		},
		{
			Name:        "kong.login.apply",
			DisplayName: "Allows applications to authenticate users",
			Secret:      "secret",
			Needs:       []string{tokens.KongProfile, tokens.KongClient},
		},
		{
			Name:        "kong.client.query",
			DisplayName: "Allows applications to get a client's needs",
			Secret:      "secret",
			Needs:       []string{tokens.KongProfile, tokens.KongClient},
		},
	}
}
