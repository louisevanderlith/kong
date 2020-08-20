package fakes

import (
	"github.com/louisevanderlith/kong/prime"
	"github.com/louisevanderlith/kong/prime/roletype"
	"github.com/louisevanderlith/kong/tokens"
)

type fakeResourceStore struct {
	Resources []prime.Resource
}

func NewFakeResources() []prime.Resource {
	return []prime.Resource{
		prime.NewResource("api.profile.view", "Displays the profile's information", "secret", nil, roletype.Nobody),
		prime.NewResource("api.user.view", "Displays the user's information", "secret", []string{tokens.UserName, tokens.UserKey, "phone"}, roletype.User),
		prime.NewResource("entity.consent.apply", "Allows applications to update consent", "secret", nil, roletype.Nobody),
		prime.NewResource("entity.login.apply", "Allows applications to authenticate users", "secret", nil, roletype.Nobody),
		prime.NewResource("entity.user.view", "Returns user information", "secret", nil, roletype.User),
		prime.NewResource("kong.client.query", "Allows applications to get a client's needs", "secret", nil, roletype.Nobody),
	}
}
