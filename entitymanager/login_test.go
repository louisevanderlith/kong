package entitymanager

import (
	"testing"
)

/*
	Login Tokens only contain the Key and Name of the User
	It has no expiry or issued-at time, because it's only a partial token
*/
func TestAuthority_Login_HasClaim_UserInfo(t *testing.T) {
	tkn, err := _manager.Login("kong.viewr", "user@fake.com", "user1pass")

	if err != nil {
		t.Error(err)
		return
	}

	k := tkn.GetUserID()

	if k != "00" {
		t.Error("invalid user key", k)
		return
	}

	n := tkn.GetDisplayName()

	if n != "User 1" {
		t.Error("invalid user name", n)
	}
}

func TestManager_Login_HasClaim_IsExpired(t *testing.T) {
	tkn, err := _manager.Login("kong.viewr", "user@fake.com", "user1pass")

	if err != nil {
		t.Error(err)
		return
	}

	if !tkn.IsExpired() {
		t.Error("user tokens must be expired, as the are only 'partial'")
		return
	}
}
