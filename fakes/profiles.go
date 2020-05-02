package fakes

import (
	"errors"
	"github.com/louisevanderlith/husk"
	"github.com/louisevanderlith/kong/prime"
	"strings"
)

type fakeProfileStore struct {
	Profiles []prime.Profile
}

func NewFakePS() fakeProfileStore {
	profs := []prime.Profile{
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

	return fakeProfileStore{profs}
}

func (ps fakeProfileStore) GetProfile(id string) (prime.Profile, error) {
	for _, v := range ps.Profiles {
		if strings.ToLower(v.Title) == id {
			return v, nil
		}
	}

	return prime.Profile{}, errors.New("profile not found")
}
