package fakes

import (
	"github.com/louisevanderlith/husk"
	"github.com/louisevanderlith/kong/prime"
)

func NewFakeProfiles() []prime.Profile {
	return []prime.Profile{
		{
			Title:       "kong",
			Description: "Rollings claims authenticator",
			Domain:      "",
			Contacts: []prime.Contact{
				{
					Icon:  "fa-facebook",
					Name:  "facebook",
					Value: "https://facebook/x",
				},
			},
			ImageKey: husk.CrazyKey(),
			Clients: []prime.Client{
				{
					Name:   "viewr",
					Secret: "secret",
					AllowedResources: []string{
						"api.profile.view",
						"api.user.view"},
				},
			},
			Endpoints: map[string]string{
				"api": "https://api.kong",
			},
			Codes: map[string]string{
				"gtag": "000000-00",
			},
		},
	}
}
