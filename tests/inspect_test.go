package tests

import (
	"kong"
	"kong/scopes"
	"testing"
)

func TestInspect_ResourceRequest(t *testing.T) {
	toknObj := kong.AccessToken{
		Client: "www",
		Scopes: []string{"theme.assets.download"},
		Claims: map[string]string{
			"profile": "kong",
		},
	}

	resrc := scopes.Resource{
		Name:        "theme.assets.download",
		DisplayName: "Download assets from Theme",
		Secret:      "secret",
		Claims:      []string{"profile"},
	}

	info, err := kong.InspectRequest(toknObj, resrc)

	if err != nil {
		t.Fatal(err)
		return
	}

	if info["profile"] != "kong"{
		t.Errorf("found %s, expected 'kong'", info["profile"])
	}
}
