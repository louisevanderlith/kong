package tests

import (
	"github.com/louisevanderlith/kong/inspectors"
	"github.com/louisevanderlith/kong/prime"
	"github.com/louisevanderlith/kong/tokens"
	"testing"
)

func TestInspect_ResourceRequest(t *testing.T) {
	toknObj := tokens.AccessToken{
		Client: "www",
		FullClaims: map[string]string{
			"profile.info.profile": "kong",
		},
	}

	resrc := prime.Resource{
		Name:        "theme.assets.download",
		DisplayName: "Download assets from Theme",
		Secret:      "secret",
		Claims:      []string{"profile.info.profile"},
	}

	ins := inspectors.NewLazyInspector()
	info, err := inspectors.InspectRequest(toknObj, resrc)

	if err != nil {
		t.Fatal(err)
		return
	}

	if info["profile.info.profile"] != "kong" {
		t.Errorf("found %s, expected 'kong'", info["profile.info.profile"])
	}
}
