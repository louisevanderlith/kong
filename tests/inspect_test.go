package tests

import (
	"github.com/louisevanderlith/kong/prime"
	"github.com/louisevanderlith/kong/tokens"
	"testing"
)

func TestInspect_ResourceRequest(t *testing.T) {
	toknObj := make(tokens.Claims)
	toknObj.AddClaim("kong.client", "www")
	toknObj.AddClaim("profile.name", "kong")

	resrc := prime.Resource{
		Name:        "theme.assets.download",
		DisplayName: "Download assets from Theme",
		Secret:      "secret",
		Needs:       []string{"profile.name"},
	}

	info, err := resrc.ExtractNeeds(toknObj)

	if err != nil {
		t.Fatal(err)
		return
	}

	act := info.GetClaim("profile.name")
	exp := "kong"
	if act != exp {
		t.Errorf("found %s, expected '%s'", act, exp)
	}
}
