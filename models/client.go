package models

import "github.com/louisevanderlith/husk"

type Client struct {
	Name         string `hsk:"size(30)"`
	Secret       string
	AllowedSopes []string
}

func (c Client) Valid() (bool, error) {
	return husk.ValidateStruct(&c)
}

func (c Client) HasScope(scope string) bool {
	for _, v := range c.AllowedSopes {
		if v == scope {
			return true
		}
	}

	return false
}
