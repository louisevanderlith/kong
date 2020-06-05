package tests

import (
	"github.com/gorilla/securecookie"
	"github.com/louisevanderlith/kong"
	"github.com/louisevanderlith/kong/tokens"
	"testing"
	"time"
)

// Should be able to Decode what we Encoded
func TestEncodeClaims_DecodeToken(t *testing.T) {
	clms := make(tokens.Claims)
	clms.AddClaim(tokens.KongProfile, "kong")
	clms.AddClaim(tokens.KongCodes, map[string]interface{}{"gtag": "000000-00"})
	clms.AddClaim(tokens.KongEndpoints, map[string]interface{}{"artifact": "http://localhost:8082", "comment": "http://localhost:8084", "comms": "http://localhost:8085", "theme": "http://localhost:8093"})
	clms.AddClaim(tokens.KongClient, "test")
	clms.AddClaim(tokens.KongID, "kong.test")
	clms.AddClaim(tokens.KongExpired, time.Now().Add(time.Minute*5))
	clms.AddClaim(tokens.KongIssued, time.Now())
	clms.AddClaim(tokens.KongTerms, map[string]interface{}{"t\u0026cs": "/terms.html"})

	k := securecookie.GenerateRandomKey(32)

	token, err := kong.EncodeClaims(k, clms)

	if err != nil {
		t.Fatal(err)
		return
	}

	outclms, err := kong.DecodeToken(k, token)

	if err != nil {
		t.Fatal(err)
		return
	}

	if !outclms.HasClaim(tokens.KongProfile) {
		t.Error("claims doesn't contain 'kong.profile'", outclms)
		return
	}
}
