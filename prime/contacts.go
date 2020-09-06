package prime

import (
	"fmt"
	"github.com/louisevanderlith/husk/validation"
)

type Contacts []Contact

func (c Contacts) ProvideClaim(claim string) (string, error) {
	for _, v := range c {
		if v.Name == claim {
			return v.Value, nil
		}
	}

	return "", fmt.Errorf("contacts: no '%s' claim found", claim)
}

//Contact holds information like email, facebook, cellphone
type Contact struct {
	Icon  string `hsk:"size(15)"`
	Name  string `hsk:"size(20)"`
	Value string `hsk:"size(256)"`
}

func (c Contact) Valid() error {
	return validation.Struct(c)
}
