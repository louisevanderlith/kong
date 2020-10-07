package entitymanager

import (
	"github.com/louisevanderlith/kong/fakes"
	"testing"
)

func TestConsent(t *testing.T) {
	InitializeManager(fakes.NewFakeUserStore())
	uclms, err := _manager.Login("kong.viewr", "user@fake.com", "user1pass")

	if err != nil {
		t.Error("Login Error", err)
		return
	}

	partial, err := _manager.Sign(uclms, 5)

	if err != nil {
		t.Error("Sign Error", err)
		return
	}

	// Apply Consent to Partial token
	usrClms, err := _manager.Consent(partial, map[string]bool{"name": true, "phone": true})

	if err != nil {
		t.Error("Consent Error", err)
		return
	}

	act := usrClms.GetClaimString("name")

	if act != "User 1" {
		t.Error("Unexpected", act)
	}

	act = usrClms.GetClaimString("phone")

	if act != "0841236789" {
		t.Error("Unexpected", act)
	}
}
