package models

import (
	"errors"
	"github.com/louisevanderlith/husk"
)

type Profile struct {
	Title       string `hsk:"size(128)"`
	Description string `hsk:"size(512)" json:",omitempty"`
	Domain      string `hsk:"size(128)"`
	Contact     Contact
	ImageKey    husk.Key `hsk:"null"`
	Clients     []Client
	Endpoints   map[string]string
	Codes       map[string]string
}

func (p Profile) Valid() (bool, error){
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

func (p Profile) GetClaim(claim string) string {
	switch claim {
	case "profile":
		return p.Title
	case "logo":
		return p.ImageKey.String()
	}

	return ""
}