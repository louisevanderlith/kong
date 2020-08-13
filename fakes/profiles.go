package fakes

import (
	"github.com/louisevanderlith/husk"
	"github.com/louisevanderlith/kong/dict"
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
					Name:         "viewr",
					Secret:       "$2a$11$JWcHYGC7K2zY4NGOD/n5puq7w8zij3GVoU9BD1j6xDtHHqFdLcV6S",
					Url:          "http://localhost:80",
					TermsEnabled: true,
					CodesEnabled: true,
					AllowedResources: []string{
						"api.profile.view",
						"api.user.view",
						"entity.user.view"},
				},
				{
					Name:   "auth",
					Secret: "$2a$11$JWcHYGC7K2zY4NGOD/n5puq7w8zij3GVoU9BD1j6xDtHHqFdLcV6S",
					Url:    "http://localhost:8094",
					AllowedResources: []string{
						"entity.consent.apply",
						"entity.login.apply",
						"entity.user.view"},
				},
			},
			Endpoints: dict.Map{
				{"api", "https://api.kong"},
				{"entity", "https://entity.kong"},
			},
			Codes: dict.Map{
				{"gtag", "000000-00"},
			},
		},
	}
}
