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
					Url:    "http://localhost:80",
					AllowedResources: []string{
						"api.profile.view",
						"api.user.view"},
				},
				{
					Name:   "auth",
					Secret: "secret",
					Url:    "http://localhost:8094",
					AllowedResources: []string{
						"kong.consent.apply",
						"kong.login.apply"},
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
