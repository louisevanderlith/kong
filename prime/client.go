package prime

import (
	"github.com/louisevanderlith/husk"
	"github.com/louisevanderlith/kong/tokens"
	"strings"
)

type Client struct {
	Name             string `hsk:"size(30)"`
	Secret           string
	AllowedResources []string
	TermsEnabled     bool
	CodesEnabled     bool
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

func (c Client) VerifySecret(secret string) bool {
	return c.Secret == secret
}

func (c Client) ExtractNeeds(p Profile) tokens.Claimer {
	result := make(tokens.Claims)

	if c.TermsEnabled {
		v, err := p.ProvideClaim(tokens.KongTerms)

		if err != nil {
			result.AddClaim(tokens.KongTerms, v)
		}
	}

	if c.CodesEnabled {
		v, err := p.ProvideClaim(tokens.KongCodes)

		if err != nil {
			result.AddClaim(tokens.KongCodes, v)
		}
	}

	for _, r := range c.AllowedResources {
		parts := strings.Split(r, ".")

		if len(parts) < 2 {
			continue
		}

		api := parts[0]
		if api == "kong" {
			continue
		}

		if result.HasClaim(api) {
			continue
		}

		v, ok := p.Endpoints[api]

		if ok {
			result.AddClaim(api, v)
		}
	}

	return result
}
