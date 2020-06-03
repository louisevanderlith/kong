package tests

import (
	"fmt"
	"github.com/louisevanderlith/kong/tokens"
	"log"
	"testing"
)

//TestAuthority_RequestToken_NoClient Tests that an error is returned when no client is found
func TestAuthority_RequestToken_NoClient(t *testing.T) {
	scp := "profile"
	_, err := authr.RequestToken("kong.xxx", "secret", "", scp)

	if err == nil {
		t.Error("error expected")
		return
	}

	if err.Error() != "no such client" {
		t.Error("unexpected error", err)
	}
}

//TestAuthority_RequestToken_HasClient Tests that the correct client is returned
func TestAuthority_RequestToken_HasClient(t *testing.T) {
	rname := "api.profile.view"
	tkn, err := authr.RequestToken("kong.viewr", "secret", "", rname)

	if err != nil {
		t.Error(err)
		return
	}

	if tkn.GetClaim(tokens.KongClient) != "viewr" {
		t.Error("incorrect client", tkn)
	}
}

//TestAuthority_RequestToken_ProfileInfo_HasAllClaims Tests that all claims for a scope is included
func TestAuthority_RequestToken_ResourceScope_HasAllClaims(t *testing.T) {
	rname := "api.profile.view"
	tkn, err := authr.RequestToken("kong.viewr", "secret", "", rname)

	if err != nil {
		t.Error(err)
		return
	}

	answr := map[string]string{
		tokens.KongProfile: "",
	}

	rsrc, _ := authr.GetStore().GetResource(rname)

	for _, v := range rsrc.Needs {
		if !tkn.HasClaim(v) {
			t.Errorf(fmt.Sprintf("'%s' claim not found", v))
			return
		}

		expct := answr[v]
		actl := tkn.GetClaim(v)
		if actl == expct {
			t.Errorf("found %s, expected %s", actl, expct)
		}
	}
}

func TestAuthority_RequestToken_UserInfo_InvalidUser(t *testing.T) {
	scp := "api.user.view"
	_, err := authr.RequestToken("kong.viewr", "secret", "", scp)

	if err == nil {
		t.Error("expected 'invalid user token'")
		return
	}
}

func TestAuthority_RequestToken_UserInfo_ValidUser_RequiresConsent(t *testing.T) {
	scp := "api.user.view"
	uclms, err := authr.Login("kong.viewr", "user@fake.com", "user1pass")

	if err != nil {
		t.Error(err)
		return
	}

	if !uclms.HasUser() {
		t.Error("invalid token, no user")
		return
	}

	utkn, err := authr.Sign(uclms)

	if err != nil {
		t.Error(err)
		return
	}

	tkn, err := authr.RequestToken("kong.viewr", "secret", utkn, scp)

	if err != nil {
		t.Error(err)
		return
	}

	answr := map[string]string{
		tokens.UserKey:  "",
		tokens.UserName: "",
	}

	rsrc, _ := authr.GetStore().GetResource(scp)
	log.Println(tkn.GetAll())
	for _, v := range rsrc.Needs {
		if !tkn.HasClaim(v) {
			t.Errorf(fmt.Sprintf("'%s' claim not found", v))
			return
		}

		expct := answr[v]
		actl := tkn.GetClaim(v)
		if actl == expct {
			t.Errorf("found %s, expected %s", actl, expct)
		}
	}
}
