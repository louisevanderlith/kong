package prime

import (
	"github.com/louisevanderlith/husk/validation"
	"golang.org/x/crypto/bcrypt"
)

type Resource struct {
	Name        string `hsk:"size(25)"`
	DisplayName string `hsk:"size(50)"`
	Secret      string
	Needs       []string
}

func NewResource(name, displayName, secret string, needs []string) Resource {
	scrt, err := bcrypt.GenerateFromPassword([]byte(secret), 11)
	if err != nil {
		panic(err)
	}

	return Resource{
		Name:        name,
		DisplayName: displayName,
		Secret:      string(scrt),
		Needs:       needs,
	}
}

func (r Resource) Valid() error {
	return validation.Struct(r)
}

func (r Resource) VerifySecret(secret string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(r.Secret), []byte(secret))
	return err == nil
}

/*
func (r Resource) ExtractNeeds(claims tokens.Claimer) (tokens.Claimer, error) {
	result := claims.GetKong()

	for _, c := range r.Needs {
		if claims.HasClaim(c) {
			result.AddClaim(c, claims.GetClaim(c))
		}
	}

	return result, nil
}

func (r Resource) AssignNeeds(usrtkn tokens.UserIdentity) (tokens.Claimer, error) {
	result := NewI make(tokens.Claims)

	for _, v := range r.Needs {
		parts := strings.Split(v, ".")

		if len(parts) != 2 {
			return nil, errors.New("scope name invalid")
		}

		sct := parts[0]

		var val interface{}
		var err error

		switch sct {
		case "kong":
			//val, err = clnt.ExtractNeeds(prof) //prof.ProvideClaim(v)
		case "user":
			if usrtkn == nil {
				return nil, errors.New("user login required")
			}

			if usrtkn.IsExpired() {
				return nil, errors.New("user token expired")
			}

			val = usrtkn.GetClaimString(v)
		}

		if err != nil {
			return nil, err
		}

		result.AddClaim(v, val)
	}

	return result, nil
}
*/
