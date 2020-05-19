package tests

import (
	"fmt"
	"github.com/louisevanderlith/kong"
	"github.com/louisevanderlith/kong/fakes"
	"github.com/louisevanderlith/kong/tokens"
	"log"
	"testing"
)

var authr kong.Author

func init() {
	a, err := kong.CreateAuthority(fakes.NewFakeStore(), "/", nil)

	if err != nil {
		panic(err)
	}

	authr = a
}

//TestAuthority_RequestToken_NoClient Tests that an error is returned when no client is found
func TestAuthority_RequestToken_NoClient(t *testing.T) {
	scp := "profile"
	_, err := authr.RequestToken("kong.xxx", "secret", make(tokens.Claims), scp)

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
	tkn, err := authr.RequestToken("kong.viewr", "secret", make(tokens.Claims), rname)

	if err != nil {
		t.Error(err)
		return
	}

	accs, err := authr.Inspect(tkn, rname, "secret")

	if err != nil {
		t.Error(err)
		return
	}

	if accs.GetClaim(tokens.KongClient) != "viewr" {
		t.Error("incorrect client", accs)
	}
}

//TestAuthority_RequestToken_ProfileInfo_HasAllClaims Tests that all claims for a scope is included
func TestAuthority_RequestToken_ResourceScope_HasAllClaims(t *testing.T) {
	rname := "api.profile.view"
	tkn, err := authr.RequestToken("kong.viewr", "secret", make(tokens.Claims), rname)

	if err != nil {
		t.Error(err)
		return
	}

	answr := map[string]string{
		tokens.KongProfile: "",
	}

	accs, err := authr.Inspect(tkn, rname, "secret")

	if err != nil {
		t.Error(err)
		return
	}

	rsrc, _ := authr.Store.GetResource(rname)

	for _, v := range rsrc.Needs {
		if !accs.HasClaim(v) {
			t.Errorf(fmt.Sprintf("'%s' claim not found", v))
			return
		}

		expct := answr[v]
		actl := accs.GetClaim(v)
		if actl == expct {
			t.Errorf("found %s, expected %s", actl, expct)
		}
	}
}

func TestAuthority_RequestToken_UserInfo_InvalidUser(t *testing.T) {
	scp := "api.user.view"
	_, err := authr.RequestToken("kong.viewr", "secret", make(tokens.Claims), scp)

	if err == nil {
		t.Error("expected 'invalid user token'")
		return
	}
}

func TestAuthority_Authorize(t *testing.T) {
	tkn, err := authr.Authorize("kong.viewr", "user@fake.com", "user1pass")

	if err != nil {
		t.Error(err)
		return
	}

	if !tkn.HasUser() {
		t.Error("token doesn't have user")
		return
	}

	k, n := tkn.GetUserinfo()

	if k != "00" {
		t.Error("invalid user key", k)
		return
	}

	if n != "User 1" {
		t.Error("invalid user name", n)
	}
}

func TestAuthority_RequestToken_UserInfo_ValidUser(t *testing.T) {
	scp := "api.user.view"
	utkn, err := authr.AuthenticateUser("user@fake.com", "user1pass")

	if err != nil {
		t.Error(err)
		return
	}

	if !utkn.HasUser() {
		t.Error("invalid token, no user")
		return
	}

	tkn, err := authr.RequestToken("kong.viewr", "secret", utkn, scp)

	if err != nil {
		t.Error(err)
		return
	}

	accs, err := authr.Inspect(tkn, "api.user.view", "secret")

	if err != nil {
		t.Error(err)
		return
	}

	answr := map[string]string{
		tokens.UserKey:  "",
		tokens.UserName: "",
	}

	rsrc, _ := authr.Store.GetResource(scp)
	log.Println(accs.GetAll())
	for _, v := range rsrc.Needs {
		if !accs.HasClaim(v) {
			t.Errorf(fmt.Sprintf("'%s' claim not found", v))
			return
		}

		expct := answr[v]
		actl := accs.GetClaim(v)
		if actl == expct {
			t.Errorf("found %s, expected %s", actl, expct)
		}
	}
}
