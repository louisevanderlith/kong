package securitymanager

import (
	"fmt"
	"github.com/louisevanderlith/kong/tokens"
	"testing"
)

//TestSecurity_RequestToken_NoClient Tests that an error is returned when no client is found
func TestSecurity_RequestToken_NoClient(t *testing.T) {
	_, err := _security.RequestToken("kong.xxx", "secret", "", map[string]bool{"api.profile.view": true})

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
	tkn, err := _security.RequestToken("kong.viewr", "secret", "", map[string]bool{"api.profile.view": true})

	if err != nil {
		t.Error(err)
		return
	}

	if tkn.GetClient() != "viewr" {
		t.Error("incorrect client", tkn)
	}
}

func TestSecurity_RequestToken_HasEndpoints(t *testing.T) {
	tkn, err := _security.RequestToken("kong.viewr", "secret", "", map[string]bool{"api.profile.view": true})

	if err != nil {
		t.Error("Request Token Error", err)
		return
	}

	url, err := tkn.GetResourceURL("api.profile.view")

	if err != nil {
		t.Error("Get Resource URL Error", err)
	}

	if url != "https://api.kong" {
		t.Error("incorrect endpoint", url)
	}
}

//TestAuthority_RequestToken_ProfileInfo_HasAllClaims Tests that all claims for a scope is included
func TestSecurity_RequestToken_ResourceScope_HasAllClaims(t *testing.T) {
	rname := "api.profile.view"

	idn, err := _security.RequestToken("kong.viewr", "secret", "", map[string]bool{rname: true})

	if err != nil {
		t.Error("Request Token Error", err)
		return
	}

	tkn, err := _security.Sign(idn, 5)

	if err != nil {
		t.Error("Sign Error", err)
		return
	}

	opn, err := _security.ClientInsight(tkn, "secret")

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
	scp := map[string]bool{"api.user.view": true}
	_, err := _security.RequestToken("kong.viewr", "secret", "", scp)

	if err == nil {
		t.Error("expected 'invalid user token'")
		return
	}

}
