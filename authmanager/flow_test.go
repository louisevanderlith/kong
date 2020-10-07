package authmanager

import (
	"github.com/louisevanderlith/kong/prime"
	"github.com/louisevanderlith/kong/stores"
	"net/http"
	"testing"
)

func init() {

	svc := stores.NewAuthService(http.DefaultClient, "", "", "kong.auth", "secret")
	InitializeManager(svc, false)
}

func TestAuthority_RequestToken_UserInfo_ValidUser_RequiresConsent(t *testing.T) {
	login := prime.LoginRequest{
		Client:   "kong.viewr",
		Username: "user@fake.com",
		Password: "user1pass",
	}

	partial, err := _authority.AuthenticateUser(login)

	if err != nil {
		t.Error("Login Error", err)
		return
	}

	// Apply Consent to Partial token
	consent := prime.QueryRequest{
		Token:  partial,
		Claims: map[string]bool{"phone": true},
	}

	usrClms, err := _authority.GiveConsent(consent)

	if err != nil {
		t.Error("Consent Error", err)
		return
	}

	if len(usrClms) == 0 {
		t.Error("user token is empty")
	}
}
