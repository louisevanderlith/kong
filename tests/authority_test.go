package tests

import (
	"fmt"
	"github.com/louisevanderlith/kong"
	"github.com/louisevanderlith/kong/fakes"
	"github.com/louisevanderlith/kong/signing"
	"github.com/louisevanderlith/kong/tokens"
	"log"
	"testing"
)

var authr kong.Authority

func init() {
	signr, err := signing.Initialize("/", false)

	if err != nil {
		panic(err)
	}

	authr = kong.Authority{
		Profiles:  fakes.NewFakePS(),
		Users:     fakes.NewFakeUS(),
		Resources: fakes.NewFakeRS(),
		SignCert:  signr,
	}
}

//TestAuthority_RequestToken_NoClient Tests that an error is returned when no client is found
func TestAuthority_RequestToken_NoClient(t *testing.T) {
	scp := "profile"
	_, err := authr.RequestToken("kong.xxx", "secret", tokens.UserToken{}, scp)

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
	rname := "api.view.profile"
	tkn, err := authr.RequestToken("kong.viewr", "secret", tokens.UserToken{}, rname)

	if err != nil {
		t.Error(err)
		return
	}

	accs, err := authr.Inspect(string(tkn), rname, "secret")

	if err != nil {
		t.Error(err)
		return
	}

	if accs.GetClaim("kong.client") != "viewr" {
		t.Error("incorrect client", accs)
	}
}

//TestAuthority_RequestToken_ProfileInfo_HasAllClaims Tests that all claims for a scope is included
func TestAuthority_RequestToken_ResourceScope_HasAllClaims(t *testing.T) {
	rname := "theme.assets.download"
	tkn, err := authr.RequestToken("kong.www", "secret", tokens.UserToken{}, rname)

	if err != nil {
		t.Error(err)
		return
	}

	answr := map[string]string{
		"profile.name": "",
	}

	accs, err := authr.Inspect(string(tkn), rname, "secret")

	if err != nil {
		t.Error(err)
		return
	}

	rsrc, _ := authr.Resources.GetResource(rname)

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
	scp := "user"
	_, err := authr.RequestToken("kong.admin", "secret", tokens.UserToken{}, scp)

	if err == nil {
		t.Error("expected 'invalid user token'")
		return
	}
}

func TestAuthority_Authorize(t *testing.T) {
	tkn, err := authr.Authorize("kong.admin", "user@fake.com", "user1pass", "user")

	if err != nil {
		t.Error(err)
		return
	}

	if tkn.Key != "00" {
		t.Error("invalid token")
	}
}

func TestAuthority_RequestToken_UserInfo_ValidUser(t *testing.T) {
	scp := "api.view.user"
	utkn, err := authr.Authorize("kong.admin", "user@fake.com", "user1pass", scp)

	if err != nil {
		t.Error(err)
		return
	}

	if utkn.Key != "00" {
		t.Error("invalid token")
	}

	tkn, err := authr.RequestToken("kong.viewr", "secret", utkn, scp)

	if err != nil {
		t.Error(err)
		return
	}

	accs, err := authr.Inspect(string(tkn), "api.view.user", "secret")

	answr := map[string]string{
		"user.name": "",
		"user.key":  "",
	}

	rsrc, _ := authr.Resources.GetResource(scp)
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
