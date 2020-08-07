package prime

import (
	"errors"
	"fmt"
	"github.com/louisevanderlith/husk"
	"github.com/louisevanderlith/kong/tokens"
	"strings"
)

type Profile struct {
	Title       string `hsk:"size(128)"`
	Description string `hsk:"size(512)" json:",omitempty"`
	Contacts    Contacts
	ImageKey    husk.Key `hsk:"null"`
	Clients     []Client
	Endpoints   Map
	Codes       Map
	Terms       Map
}

func (p Profile) Valid() error {
	return husk.ValidateStruct(&p)
}

func (p Profile) GetClient(id string) (Client, error) {
	for _, v := range p.Clients {
		if v.Name == id {
			return v, nil
		}
	}

	return Client{}, errors.New("no such client")
}

func (p Profile) GetClientClaims(c Client) tokens.Claims {
	result := tokens.EmptyClaims()

	v, _ := p.ProvideClaim(tokens.KongLogo)
	result.AddClaim(tokens.KongLogo, v)

	if c.TermsEnabled {
		v, _ := p.ProvideClaim(tokens.KongTerms)
		result.AddClaim(tokens.KongTerms, v)
	}

	if c.CodesEnabled {
		v, _ := p.ProvideClaim(tokens.KongCodes)
		result.AddClaim(tokens.KongCodes, v)
	}

	result.AddClaim(tokens.KongContacts, p.Contacts)

	if len(c.AllowedResources) > 0 {
		ends := make(map[string]string)
		for _, r := range c.AllowedResources {
			parts := strings.Split(r, ".")

			if len(parts) < 2 {
				continue
			}

			api := parts[0]
			if api == "kong" {
				continue
			}

			v := p.Endpoints.Get(api)

			if len(v) > 0 {
				ends[api] = v
			}
		}

		result.AddClaim(tokens.KongEndpoints, ends)
	}

	return result
}

func (p Profile) ProvideClaim(claim string) (interface{}, error) {
	switch claim {
	case tokens.KongProfile:
		return p.Title, nil
	case tokens.KongLogo:
		return p.ImageKey.String(), nil
	case tokens.KongTerms:
		return p.Terms, nil
	case tokens.KongCodes:
		return p.Codes, nil
	case tokens.KongEndpoints:
		return p.Endpoints, nil
	default:
		return p.Contacts.ProvideClaim(claim)
	}

	return "", fmt.Errorf("profile: no '%s' claim found", claim)
}
