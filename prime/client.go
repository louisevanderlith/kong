package prime

import (
	"github.com/louisevanderlith/husk"
	"github.com/louisevanderlith/kong/tokens"
	"golang.org/x/crypto/bcrypt"
	"strings"
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

func (c Client) VerifySecret(secret string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(c.Secret), []byte(secret))
	return err == nil
}

func (c Client) ExtractNeeds(p Profile) tokens.Claimer {
	result := make(tokens.Claims)

	if c.TermsEnabled {
		v, _ := p.ProvideClaim(tokens.KongTerms)
		result.AddClaim(tokens.KongTerms, v)
	}

	if c.CodesEnabled {
		v, _ := p.ProvideClaim(tokens.KongCodes)
		result.AddClaim(tokens.KongCodes, v)
	}

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

			v, ok := p.Endpoints[api]

			if ok {
				ends[api] = v
			}
		}

		result.AddClaim(tokens.KongEndpoints, ends)
	}

	return result
}
