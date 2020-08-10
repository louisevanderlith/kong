package man

import (
	"github.com/louisevanderlith/kong/samples/servers/entity"
	"testing"
)

func TestConsent(t *testing.T) {
	uclms, err := entity.Manager.Login("kong.viewr", "user@fake.com", "user1pass")

	if err != nil {
		t.Error("Login Error", err)
		return
	}

	partial, err := entity.Manager.Sign(uclms, 5)

	if err != nil {
		t.Error("Sign Error", err)
		return
	}

	// Apply Consent to Partial token
	usrClms, err := entity.Manager.Consent(partial, map[string]bool{"phone": true})

	if err != nil {
		t.Error("Consent Error", err)
		return
	}

	act := usrClms.GetClaimString("phone")

	if act != "0841236789" {
		t.Error("Unexpected", act)
	}
}
