package prime

import (
	"encoding/json"
	"errors"
	"github.com/louisevanderlith/husk"
	"github.com/louisevanderlith/kong/tokens"
)

type Profile struct {
	Title       string `hsk:"size(128)"`
	Description string `hsk:"size(512)" json:",omitempty"`
	Domain      string `hsk:"size(128)"`
	Contacts    Contacts
	ImageKey    husk.Key `hsk:"null"`
	Clients     []Client
	Endpoints   map[string]string
	Codes       map[string]string
	Terms       map[string]string
}

func (p Profile) Valid() (bool, error) {
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

func (p Profile) ProvideClaim(claim string) (string, error) {
	switch claim {
	case tokens.KongProfile:
		return p.Title, nil
	case tokens.KongLogo:
		return p.ImageKey.String(), nil
	case tokens.KongTerms:
		ts, err := json.Marshal(p.Terms)

		if err != nil {
			return "", err
		}

		return string(ts), nil
	case tokens.KongCodes:
		cds, err := json.Marshal(p.Codes)

		if err != nil {
			return "", err
		}

		return string(cds), nil
	case tokens.KongEndpoints:
		points, err := json.Marshal(p.Endpoints)

		if err != nil {
			return "", err
		}

		return string(points), nil
	default:
		return p.Contacts.ProvideClaim(claim)
	}

	return "", errors.New("no claim found")
}
