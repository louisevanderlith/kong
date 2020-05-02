package tests

import (
	"github.com/louisevanderlith/kong/prime"
	"github.com/louisevanderlith/kong/tokens"
	"testing"
)

func TestInspect_ResourceRequest(t *testing.T) {
	toknObj := make(tokens.Claims)
	toknObj.AddClaim(tokens.KongClient, "viewr")
	toknObj.AddClaim(tokens.KongProfile, "kong")

	resrc := prime.Resource{
		Name:        "api.profile.view",
		DisplayName: "Displays the profile's information",
		Secret:      "secret",
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
