package tests

import (
	"fmt"
	"kong/scopes"
)

type fakeScopeStore struct {
	Scopes []scopes.Scoper
}

func newFakeSS() fakeScopeStore {
	scps := []scopes.Scoper{
		scopes.Known{
			Name:        "profile.info",
			DisplayName: "Profile information",
			Secret:      "secret",
			Claims:      []string{"profile", "logo"},
		},
		scopes.Known{
			Name:        "profile.api",
			DisplayName: "Profile API Mapping",
			Secret:      "secret",
			Claims:      []string{"endpoints", "codes", "terms"},
		},
		scopes.Known{
			Name:        "profile.contact",
			DisplayName: "Profile Contact Details",
			Secret:      "secret",
			Claims:      []string{"email", "facebook", "twitter", "cellphone", "whatsapp"},
		},
		scopes.Known{
			Name:        "user.info",
			DisplayName: "Requires a user to login",
			Secret:      "secret",
			Claims:      []string{"username", "userkey"},
		},
		scopes.Known{
			Name:        "user.contact",
			DisplayName: "User Contact Details",
			Secret:      "secret",
			Claims:      []string{"email", "facebook", "twitter", "cellphone", "whatsapp"},
		},
		scopes.Resource{
			Name:        "theme.assets.download",
			DisplayName: "Download Theme assets",
			Secret:      "secret",
			Claims:      []string{"profile"},
		},
		scopes.Resource{
			Name:        "theme.assets.view",
			DisplayName: "View Theme assets",
			Secret:      "secret",
			Claims:      []string{"profile"},
		},
		scopes.Resource{
			Name:        "artifact.download",
			DisplayName: "Download Artifacts",
			Secret:      "secret",
			Claims:      nil,
		},
	}
	return fakeScopeStore{scps}
}

func (s fakeScopeStore) GetScope(name string) (scopes.Scoper, error) {
	for _, v := range s.Scopes {
		if v.GetName() == name {
			return v, nil
		}
	}

	return nil, fmt.Errorf("scope %s not found", name)
}
