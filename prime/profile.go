package prime

import (
	"encoding/json"
	"errors"
	"github.com/louisevanderlith/husk"
	"log"
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
	Terms       []string
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

func (p Profile) ProvideClaim(claim string) string {
	result := ""

	switch claim {
	case "name":
		result = p.Title
	case "logo":
		result = p.ImageKey.String()
	case "terms":
		ts, err := json.Marshal(p.Terms)

		if err != nil {
			log.Println(err)
			return ""
		}

		result = string(ts)
	case "codes":
		cds, err := json.Marshal(p.Codes)

		if err != nil {
			log.Println(err)
			return ""
		}

		result = string(cds)
	case "endpoints":
		points, err := json.Marshal(p.Endpoints)

		if err != nil {
			log.Println(err)
			return ""
		}

		result = string(points)
	default:
		result = p.Contacts.ProvideClaim(claim)
	}

	return result
}
