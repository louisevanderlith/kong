package prime

import "github.com/louisevanderlith/husk"

type Contacts []Contact

func (c Contacts) ProvideClaim(claim string) string {
	for _, v := range c {
		if v.Name == claim {
			return v.Value
		}
	}

	return ""
}

//Contact holds information like email, facebook, cellphone
type Contact struct {
	Icon  string `hsk:"size(15)"`
	Name  string `hsk:"size(20)"`
	Value string `hsk:"size(256)"`
}

func (c Contact) Valid() (bool, error) {
	return husk.ValidateStruct(&c)
}
