package tests

import (
	"github.com/louisevanderlith/kong/prime"
	"github.com/louisevanderlith/kong/tokens"
	"testing"
)

func TestAuthority_Inspect_ResourceRequest(t *testing.T) {
	toknObj := make(tokens.Claims)
	toknObj.AddClaim(tokens.KongClient, "viewr")
	toknObj.AddClaim(tokens.KongProfile, "kong")

	resrc := prime.Resource{
		Name:        "api.profile.view",
		DisplayName: "Displays the profile's information",
		Secret:      "$2a$11$JWcHYGC7K2zY4NGOD/n5puq7w8zij3GVoU9BD1j6xDtHHqFdLcV6S",
		Needs:       []string{tokens.KongProfile, tokens.KongClient},
	}

	info, err := resrc.ExtractNeeds(toknObj)

	if err != nil {
		t.Fatal(err)
		return
	}

	act := info.GetClaim(tokens.KongProfile)
	exp := "kong"
	if act != exp {
		t.Errorf("found %s, expected '%s'", act, exp)
	}
}

func TestAuthority_Inspect_ReturnsTokenClaims(t *testing.T) {
	rname := "api.profile.view"
	tkn, err := authr.RequestToken("kong.viewr", "secret", "", rname)

	if err != nil {
		t.Error(err)
		return
	}

	stkn, err := authr.Sign(tkn)

	if err != nil {
		t.Error(err)
		return
	}

	clms, err := authr.Inspect(stkn, rname, "secret")

	if err != nil {
		t.Error(err)
		return
	}

	hasProfile := clms.HasClaim(tokens.KongProfile)

	if !hasProfile {
		t.Error("no profile")
		return
	}

	hasClient := clms.HasClaim(tokens.KongClient)

	if !hasClient {
		t.Error("no client")
		return
	}
}
