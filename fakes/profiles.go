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
					Secret: "$2a$11$JWcHYGC7K2zY4NGOD/n5puq7w8zij3GVoU9BD1j6xDtHHqFdLcV6S",
					Url:    "http://localhost:80",
					AllowedResources: []string{
						"api.profile.view",
						"api.user.view"},
				},
				{
					Name:   "auth",
					Secret: "$2a$11$JWcHYGC7K2zY4NGOD/n5puq7w8zij3GVoU9BD1j6xDtHHqFdLcV6S",
					Url:    "http://localhost:8094",
					AllowedResources: []string{
						"kong.consent.apply",
						"kong.login.apply"},
				},
			},
			Endpoints: prime.Map{
				{"api", "https://api.kong"},
			},
			Codes: prime.Map{
				{"gtag", "000000-00"},
			},
		},
	}
}
