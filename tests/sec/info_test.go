package sec

import (
	"github.com/louisevanderlith/kong/samples/servers/secure"
	"github.com/louisevanderlith/kong/tokens"
	"testing"
)

func TestAuthority_Info(t *testing.T) {
	tkn, err := secure.Security.RequestToken("kong.viewr", "secret", "", map[string]bool{"api.profile.view": true})

	if err != nil {
		t.Error(err)
		return
	}

	stkn, err := secure.Security.Sign(tkn, 5)

	if err != nil {
		t.Error("Sign Error", err)
		return
	}

	clms, err := secure.Security.ClientInsight(stkn, "secret")

	if err != nil {
		t.Error("Info Error", err)
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
