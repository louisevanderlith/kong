package prime

import (
	"errors"
	"github.com/louisevanderlith/kong/tokens"
	"strings"
)

type Resource struct {
	Name        string
	DisplayName string
	Secret      string
	Needs       []string
}

func (r Resource) VerifySecret(secret string) bool {
	return r.Secret == secret
}

func (r Resource) ExtractNeeds(claims tokens.Claimer) (tokens.Claimer, error) {
	result := claims.GetKong()

	for _, c := range r.Needs {
		if claims.HasClaim(c) {
			result.AddClaim(c, claims.GetClaim(c))
		}
	}

	return result, nil
}

func (r Resource) AssignNeeds(prof Profile, userKey string, usr User) (tokens.Claimer, error) {
	result := make(tokens.Claims)

	for _, v := range r.Needs {
		parts := strings.Split(v, ".")

		if len(parts) != 2 {
			return nil, errors.New("scope name invalid")
		}

		sct := parts[0]
		clm := parts[1]
		val := ""
		var err error
		switch sct {
		case "profile":
			val, err = prof.ProvideClaim(clm)
		case "user":
			if usr != nil && usr.IsVerified() {
				if clm == "key" {
					val = userKey
				} else {
					val, err = prof.ProvideClaim(clm)
				}
			} else {
				return nil, errors.New("user is not verified")
			}
		}

		if err != nil {
			return nil, err
		}

		result.AddClaim(v, val)
	}

	return result, nil
}
