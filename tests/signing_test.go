package tests

import (
	"fmt"
	"github.com/gorilla/securecookie"
	"github.com/louisevanderlith/kong/tokens"
	"testing"
)

func TestEncodeClaims_Decode_MustHaveAllClaims(t *testing.T){
	clms, err := tokens.NewIdentity("kong.test")
	clms.AddClaim(tokens.KongCodes, map[string]interface{}{"gtag": "000000-00"})
	clms.AddClaim(tokens.KongEndpoints, map[string]interface{}{"artifact": "http://localhost:8082", "comment": "http://localhost:8084", "comms": "http://localhost:8085", "theme": "http://localhost:8093"})
	clms.AddClaim(tokens.KongTerms, map[string]interface{}{"t\u0026cs": "/terms.html"})

	k := securecookie.GenerateRandomKey(32)

	token, err := tokens.IssueClaims(k, clms, 5)

	if err != nil {
		t.Fatal(err)
		return
	}

	outclms := tokens.EmptyClaims()
	err = tokens.DecodeToken(k, token, outclms)

	if err != nil {
		t.Fatal(err)
		return
	}

	have := []string{
		tokens.KongID,
		tokens.KongProfile,
		tokens.KongClient,
		tokens.KongIssued,
		tokens.KongExpired,
		tokens.KongCodes,
		tokens.KongCodes,
		tokens.KongEndpoints,
	}

	for _, h := range have {
		if !outclms.HasClaim(h) {
			t.Error(fmt.Sprintf("claims doesn't contain '%s'", h))
			return
		}
	}
}

// Should be able to Decode what we Encoded
func TestEncodeClaims_DecodeToken(t *testing.T) {
	clms, err := tokens.NewIdentity("kong.test")
	clms.AddClaim(tokens.KongCodes, map[string]interface{}{"gtag": "000000-00"})
	clms.AddClaim(tokens.KongEndpoints, map[string]interface{}{"artifact": "http://localhost:8082", "comment": "http://localhost:8084", "comms": "http://localhost:8085", "theme": "http://localhost:8093"})
	clms.AddClaim(tokens.KongTerms, map[string]interface{}{"t\u0026cs": "/terms.html"})

	k := securecookie.GenerateRandomKey(32)

	token, err := tokens.IssueClaims(k, clms, 5)

	if err != nil {
		t.Fatal(err)
		return
	}

	outclms := tokens.EmptyClaims()
	err = tokens.DecodeToken(k, token, outclms)

	if err != nil {
		t.Fatal(err)
		return
	}

	if !outclms.HasClaim(tokens.KongProfile) {
		t.Error("claims doesn't contain 'kong.profile'", outclms)
		return
	}
}
