package sec

import (
	"fmt"
	"github.com/louisevanderlith/kong/samples/servers/entity"
	"github.com/louisevanderlith/kong/samples/servers/secure"
	"github.com/louisevanderlith/kong/tokens"
	"testing"
)

//TestSecurity_RequestToken_NoClient Tests that an error is returned when no client is found
func TestSecurity_RequestToken_NoClient(t *testing.T) {
	scp := "profile"
	_, err := secure.Security.RequestToken("kong.xxx", "secret", "", scp)

	if err == nil {
		t.Error("error expected")
		return
	}

	if err.Error() != "no such client" {
		t.Error("unexpected error", err)
	}
}

//TestAuthority_RequestToken_HasClient Tests that the correct client is returned
func TestSecurity_RequestToken_HasClient(t *testing.T) {
	rname := "api.profile.view"
	tkn, err := secure.Security.RequestToken("kong.viewr", "secret", "", rname)

	if err != nil {
		t.Error(err)
		return
	}

	if tkn.GetClient() != "viewr" {
		t.Error("incorrect client", tkn)
	}
}

//TestAuthority_RequestToken_ProfileInfo_HasAllClaims Tests that all claims for a scope is included
func TestSecurity_RequestToken_ResourceScope_HasAllClaims(t *testing.T) {
	rname := "api.profile.view"

	idn, err := secure.Security.RequestToken("kong.viewr", "secret", "", rname)

	if err != nil {
		t.Error("Request Token Error", err)
		return
	}

	tkn, err := secure.Security.Sign(idn, 5)

	if err != nil {
		t.Error("Sign Error", err)
		return
	}

	opn, err := secure.Security.Info(tkn, "secret")

	if err != nil {
		t.Error("Info Error", err)
		return
	}

	answr := map[string]string{
		tokens.KongProfile:   "",
		tokens.KongEndpoints: "",
		tokens.KongLogo:      "",
		tokens.KongID:        "",
		tokens.KongClient:    "",
		tokens.KongTerms:     "",
		tokens.KongIssued:    "",
		tokens.KongExpired:   "",
		tokens.KongCodes:     "",
		tokens.KongContacts:  "",
	}

	for k, v := range answr {
		if !opn.HasClaim(k) {
			t.Errorf(fmt.Sprintf("'%s' claim not found", k))
			return
		}

		val := opn.GetClaim(k)

		if val == v {
			t.Error("Claim Empty", val)
		}
	}
}

func TestSecurity_RequestToken_UserInfo_InvalidUser(t *testing.T) {
	scp := "api.user.view"
	_, err := secure.Security.RequestToken("kong.viewr", "secret", "", scp)

	if err == nil {
		t.Error("expected 'invalid user token'")
		return
	}
}

func TestSecurity_RequestToken_UserInfo_ValidUser_RequiresConsent(t *testing.T) {
	scp := "api.user.view"
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

	utkn, err := entity.Manager.Sign(usrClms, 5)

	if err != nil {
		t.Error("Sign Error", err)
		return
	}

	tkn, err := secure.Security.RequestToken("kong.viewr", "secret", utkn, scp)

	if err != nil {
		t.Error("Request Token Error", err)
		return
	}

	if !tkn.HasUser() {
		t.Error("no user found")
		return
	}

	assignd, err := entity.Manager.FetchNeeds(tkn.GetUserToken(), "phone")

	if err != nil {
		t.Error("Fetch Needs Error", err)
		return
	}

	answr := map[string]string{
		tokens.UserKey:  "",
		tokens.UserName: "",
		"phone":         "",
	}

	for k, v := range answr {
		if !assignd.HasClaim(k) {
			t.Errorf(fmt.Sprintf("'%s' claim not found", k))
			return
		}

		actl := assignd.GetClaim(k)

		if actl == v {
			t.Errorf("actual is empty %s", actl)
		}
	}
}
