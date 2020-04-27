package tests

import (
	"fmt"
	"github.com/louisevanderlith/kong"
	"github.com/louisevanderlith/kong/fakes"
	"github.com/louisevanderlith/kong/tokens"
	"testing"
)

var authr kong.Authority

func init() {
	authr = kong.Authority{
		Profiles:  fakes.NewFakePS(),
		Users:     fakes.NewFakeUS(),
		Resources: fakes.NewFakeRS(),
	}
}

//TestAuthority_RequestToken_NoClient Tests that an error is returned when no client is found
func TestAuthority_RequestToken_NoClient(t *testing.T) {
	scp := "profile.info"
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
	scp := "profile.info"
	tkn, err := authr.RequestToken("kong.www", "secret", tokens.UserToken{}, scp)

	if err != nil {
		t.Error(err)
		return
	}

	claims, err := authr.Spill(string(tkn))

	if err != nil {
		t.Error(err)
		return
	}

	if claims["kong.info.client"] != "www" {
		t.Error("incorrect client", claims["kong.info.client"])
	}
}

//TestAuthority_RequestToken_ProfileInfo_HasAllClaims Tests that all claims for a scope is included
func TestAuthority_RequestToken_ProfileInfo_HasAllClaims(t *testing.T) {
	resource := "profile.info"
	accs, err := authr.RequestToken("kong.www", "secret", tokens.UserToken{}, scp)

	if err != nil {
		t.Error(err)
		return
	}

	answr := map[string]string{
		"profile.info.profile": "",
		"profile.info.logo":    "0`0",
	}

	fScop, _ := authr.Resources.GetResource(scp)

	for _, v := range fScop.GetClaims() {
		fullName := scp + "." + v
		if !accs.HasClaim(fullName) {
			t.Errorf(fmt.Sprintf("'%s' claim not found", v))
			return
		}

		expct := answr[fullName]
		actl := accs.GetClaim(fullName)
		if actl == expct {
			t.Errorf("found %s, expected %s", actl, expct)
		}
	}
}

//TestAuthority_RequestToken_ProfileInfo_HasAllClaims Tests that all claims for a scope is included
func TestAuthority_RequestToken_ResourceScope_HasAllClaims(t *testing.T) {
	scp := "theme.assets.download"
	accs, err := authr.RequestToken("kong.www", "secret", tokens.UserToken{}, scp)

	if err != nil {
		t.Error(err)
		return
	}

	answr := map[string]string{
		"profile": "",
	}

	fScop, _ := authr.Scopes.GetScope(scp)

	for _, v := range fScop.GetClaims() {
		fullName := scp + "." + v
		if !accs.HasClaim(fullName) {
			t.Errorf(fmt.Sprintf("'%s' claim not found", v))
			return
		}

		expct := answr[fullName]
		actl := accs.GetClaim(fullName)
		if actl == expct {
			t.Errorf("found %s, expected %s", actl, expct)
		}
	}
}

func TestAuthority_RequestToken_UserInfo_InvalidUser(t *testing.T) {
	scp := "user.info"
	_, err := authr.RequestToken("kong.admin", "secret", tokens.UserToken{}, scp)

	if err == nil {
		t.Error("expected 'invalid user token'")
		return
	}
}

func TestAuthority_Authorize(t *testing.T) {
	tkn, err := authr.Authorize("kong.admin", "user@fake.com", "user1pass", "user.info")

	if err != nil {
		t.Error(err)
		return
	}

	if tkn.Key != "00" {
		t.Error("invalid token")
	}
}

func TestAuthority_RequestToken_UserInfo_ValidUser(t *testing.T) {
	scp := "user.info"
	tkn, err := authr.Authorize("kong.admin", "user@fake.com", "user1pass", scp)

	if err != nil {
		t.Error(err)
		return
	}

	if tkn.Key != "00" {
		t.Error("invalid token")
	}

	accs, err := authr.RequestToken("kong.admin", "secret", tkn, scp)

	if err != nil {
		t.Error(err)
		return
	}

	answr := map[string]string{
		"user.info.username": "",
		"user.info.userkey":  "",
	}

	fScop, _ := authr.Scopes.GetScope(scp)

	for _, v := range fScop.GetClaims() {
		fullName := scp + "." + v
		if !accs.HasClaim(fullName) {
			t.Errorf(fmt.Sprintf("'%s' claim not found", v))
			return
		}

		expct := answr[fullName]
		actl := accs.GetClaim(fullName)
		if actl == expct {
			t.Errorf("found %s, expected %s", actl, expct)
		}
	}
}
