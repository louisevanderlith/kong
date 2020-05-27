package tests

import (
	"github.com/louisevanderlith/kong/tokens"
	"testing"
)

/*
	Client Application flow that requires user login to call a resource.
	This is the fullest flow, and the reason kong was built.
	1. Browser hits Client Middleware.
	2. ObtainToken (Will fail, as user or consent is not provided)
	3. Consent (To obtain user's consent on Scopes and their claims)
	4. Login (Displays Login)
	5. AuthenticateUser (Login POST)
	6. Consent (Displays the application's required scopes to user)
	7. AuthorizeConsent (Consent POST)
	8. Send UserToken to Client (Callback)
	9. Goto 1.
*/

func TestFlow_User(t *testing.T) {
	appId := "kong.viewr"
	// Try to obtain token, should fail since we're requesting a user claim
	_, err := authr.RequestToken(appId, "secret", make(tokens.Claims), "api.user.view")

	if err == nil {
		t.Error("unexpected success, user should be required")
		return
	}

	// Obtain Partial login Token
	partial, err := authr.Login(appId, "user@fake.com", "user1pass")

	if err != nil {
		t.Error(err)
		return
	}

	// Apply Consent to Partial token
	ut, err := authr.Consent(partial, tokens.KongProfile, tokens.KongClient, tokens.UserName, tokens.UserKey)

	if err != nil {
		t.Error(err)
		return
	}

	tkn, err := authr.RequestToken(appId, "secret", ut, "api.user.view")

	if err != nil {
		t.Error(err)
		return
	}

	if !tkn.HasClaim(tokens.UserName) {
		t.Error("token doesn't have 'UserName' claim")
		return
	}

	act := tkn.GetClaim(tokens.UserName)
	exp := "User 1"
	if  act != exp {
		t.Errorf("incorrect claim; want %s, got %s", exp, act)
		return
	}
}
