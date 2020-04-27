package prime

import "github.com/louisevanderlith/husk"

type Client struct {
	Name             string `hsk:"size(30)"`
	Secret           string
	AllowedResources []string
}

func (c Client) Valid() (bool, error) {
	return husk.ValidateStruct(&c)
}

func (c Client) ResourceAllowed(resource string) bool {
	for _, v := range c.AllowedResources {
		if v == resource {
			return true
		}
	}

	return false
}
