package prime

import (
	"github.com/louisevanderlith/husk/validation"
	"golang.org/x/crypto/bcrypt"
)

type Client struct {
	Name             string `hsk:"size(30)"`
	Secret           string
	Url              string `hsk:"size(128)"`
	AllowedResources []string
	TermsEnabled     bool
	CodesEnabled     bool
}

func NewClient(name, secret, url string, terms, codes bool, resources []string) Client {
	scrt, err := bcrypt.GenerateFromPassword([]byte(secret), 11)
	if err != nil {
		panic(err)
	}

	return Client{
		Name:             name,
		Secret:           string(scrt),
		Url:              url,
		TermsEnabled:     terms,
		CodesEnabled:     codes,
		AllowedResources: resources,
	}
}

func (c Client) Valid() error {
	return validation.Struct(c)
}

func (c Client) ResourceAllowed(resource string) bool {
	for _, v := range c.AllowedResources {
		if v == resource {
			return true
		}
	}

	return false
}

func (c Client) VerifySecret(secret string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(c.Secret), []byte(secret))
	return err == nil
}
