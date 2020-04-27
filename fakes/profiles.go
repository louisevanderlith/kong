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
					Name:   "www",
					Secret: "secret",
					AllowedSopes: []string{
						"profile.info",
						"comms.messages.create",
						"blog.articles.view",
						"blog.articles.search",
						"comment.messages.search",
						"theme.assets.download",
						"theme.assets.view",
						"artifact.download"},
				},
				{
					Name:   "admin",
					Secret: "secret",
					AllowedSopes: []string{
						"profile.info",
						"user.info"},
				},
			},
			Endpoints: map[string]string{
				"comms":    "https://comms.kong",
				"blog":     "https://blog.kong",
				"theme":    "https://theme.kong",
				"artifact": "https://artifact.kong",
				"comment":  "https://comment.kong",
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
