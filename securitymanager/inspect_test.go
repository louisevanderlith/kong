package securitymanager

import (
	"github.com/louisevanderlith/kong/tokens"
	"testing"
)

func TestAuthority_Inspect_ReturnsTokenClaims(t *testing.T) {
	rname := "api.profile.view"

	tkn, err := _security.RequestToken("kong.viewr", "secret", "", map[string]bool{"api.profile.view": true})

	if err != nil {
		t.Error("Request Token Error", err)
		return
	}

	stkn, err := _security.Sign(tkn, 5)

	if err != nil {
		t.Error("Sign Error", err)
		return
	}

	clms, err := _security.ResourceInsight(stkn, rname, "secret")

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

	val, err := clms.GetCode("gtag")

	if err != nil {
		t.Error("Get Code Error", err)
		return
	}

	if val != "000000-00" {
		t.Error("invalid value", val)
	}
}
