package prime

import (
	"errors"
	"fmt"
	"github.com/louisevanderlith/husk"
	"github.com/louisevanderlith/kong/tokens"
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
