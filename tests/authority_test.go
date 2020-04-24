package tests

import (
	"fmt"
	"kong"
	"testing"
)

var authr kong.Authority

func init() {
	authr = kong.Authority{
		Profiles: newFakePS(),
		Users:    newFakeUS(),
		Scopes:   newFakeSS(),
	}
}

//TestAuthority_RequestToken_NoClient Tests that an error is returned when no client is found
func TestAuthority_RequestToken_NoClient(t *testing.T) {
	scp := "profile.info"
	_, err := authr.RequestToken("kong.xxx", "secret", kong.UserToken{}, scp)

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
	accs, err := authr.RequestToken("kong.www", "secret", kong.UserToken{}, scp)

	if err != nil {
		t.Error(err)
		return
	}

	if accs.GetClient() != "www" {
		t.Error("incorrect client", accs.GetClient())
	}
}

//TestAuthority_RequestToken_ProfileInfo_HasAllClaims Tests that all claims for a scope is included
func TestAuthority_RequestToken_ProfileInfo_HasAllClaims(t *testing.T) {
	scp := "profile.info"
	accs, err := authr.RequestToken("kong.www", "secret", kong.UserToken{}, scp)

	if err != nil {
		t.Error(err)
		return
	}

	answr := map[string]string{
		"profile": "",
		"logo":    "0`0",
	}

	fScop, _ := authr.Scopes.GetScope(scp)

	for _, v := range fScop.GetClaims() {
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

//TestAuthority_RequestToken_ProfileInfo_HasAllClaims Tests that all claims for a scope is included
func TestAuthority_RequestToken_ResourceScope_HasAllClaims(t *testing.T) {
	scp := "theme.assets.download"
	accs, err := authr.RequestToken("kong.www", "secret", kong.UserToken{}, scp)

	if err != nil {
		t.Error(err)
		return
	}

	answr := map[string]string{
		"profile": "",
	}

	fScop, _ := authr.Scopes.GetScope(scp)

	for _, v := range fScop.GetClaims() {
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
	scp := "user.info"
	_, err := authr.RequestToken("kong.admin", "secret", kong.UserToken{}, scp)

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
		"username": "",
		"userkey":  "",
	}

	fScop, _ := authr.Scopes.GetScope(scp)

	for _, v := range fScop.GetClaims() {
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
