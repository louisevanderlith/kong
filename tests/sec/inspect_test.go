package sec

import (
	"github.com/louisevanderlith/kong/samples/servers/secure"
	"github.com/louisevanderlith/kong/tokens"
	"testing"
)

func TestAuthority_Inspect_ReturnsTokenClaims(t *testing.T) {
	rname := "api.profile.view"

	tkn, err := secure.Security.RequestToken("kong.viewr", "secret", "", rname)

	if err != nil {
		t.Error("Request Token Error", err)
		return
	}

	stkn, err := secure.Security.Sign(tkn, 5)

	if err != nil {
		t.Error("Sign Error", err)
		return
	}

	clms, err := secure.Security.Inspect(stkn, rname, "secret")

	if err != nil {
		t.Error("Inspect Error", err)
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
