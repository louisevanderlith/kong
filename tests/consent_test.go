package tests

import (
	"github.com/louisevanderlith/kong/tokens"
	"testing"
)

/*
	Consent Tokens receive empty values on consented claims
	User Key, Name and client should always be populated
*/

//UserInfo must always have a value. User's can't deny these claims.
func TestAuthority_Consent_HasClaimValue_UserInfo(t *testing.T) {
	partClms, err := authr.Login("kong.viewr", "user@fake.com", "user1pass")

	if err != nil {
		t.Error(err)
		return
	}

	partial, err := authr.Sign(partClms)

	if err != nil {
		t.Error(err)
		return
	}

	// Apply Consent to Partial token
	usrClms, err := authr.Consent(partial, tokens.KongProfile, tokens.KongClient, tokens.UserName, tokens.UserKey)

	if err != nil {
		t.Error(err)
		return
	}

	if !usrClms.HasUser() {
		t.Error("token doesn't have user")
		return
	}

	k, n := usrClms.GetUserinfo()

	if k != "00" {
		t.Error("invalid user key", k)
		return
	}

	if n != "User 1" {
		t.Error("invalid user name", n)
	}
}

//Client must always be populated. User's can't deny these claims.
func TestAuthority_Consent_HasClaimValue_Client(t *testing.T) {
	partClms, err := authr.Login("kong.viewr", "user@fake.com", "user1pass")

	if err != nil {
		t.Error(err)
		return
	}

	partial, err := authr.Sign(partClms)

	if err != nil {
		t.Error(err)
		return
	}

	// Apply Consent to Partial token
	usrClms, err := authr.Consent(partial, tokens.KongProfile, tokens.KongClient, tokens.UserName, tokens.UserKey, "user.contact")

	if err != nil {
		t.Error(err)
		return
	}

	if !usrClms.HasClaim(tokens.KongID) {
		t.Error("must have claim 'kong.id'")
		return
	}

	if usrClms.GetClaimString(tokens.KongID) != "kong.viewr" {
		t.Error("claims value invalid")
		return
	}
}

//Claims that are consented, should appear in the token, but have no value.
func TestAuthority_Consent_HasClaim_NoValue_Consented(t *testing.T) {
	partClms, err := authr.Login("kong.viewr", "user@fake.com", "user1pass")

	if err != nil {
		t.Error(err)
		return
	}

	partial, err := authr.Sign(partClms)

	if err != nil {
		t.Error(err)
		return
	}

	// Apply Consent to Partial token
	usrClms, err := authr.Consent(partial, tokens.KongProfile, tokens.KongClient, tokens.UserName, tokens.UserKey, "user.contact.facebook")

	if err != nil {
		t.Error(err)
		return
	}

	if !usrClms.HasClaim("user.contact.facebook") {
		t.Error("must have claim 'user.contact.facebook'")
		return
	}

	if usrClms.GetClaimString("user.contact.facebook") != "" {
		t.Error("claims value invalid")
		return
	}
}

//Claims that are not consented, shouldn't appear in the token
func TestAuthority_Consent_NoClaim_NotConsented(t *testing.T) {
	partClms, err := authr.Login("kong.viewr", "user@fake.com", "user1pass")

	if err != nil {
		t.Error(err)
		return
	}

	partial, err := authr.Sign(partClms)

	if err != nil {
		t.Error(err)
		return
	}

	// Apply Consent to Partial token
	usrClms, err := authr.Consent(partial, tokens.KongProfile, tokens.KongClient, tokens.UserName, tokens.UserKey)

	if err != nil {
		t.Error(err)
		return
	}

	if usrClms.HasClaim("user.contact.facebook") {
		t.Error("'user.contact' not consented")
		return
	}
}
