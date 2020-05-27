package tests

import "testing"

func TestAuthority_Login(t *testing.T) {
	tkn, err := authr.Login("kong.viewr", "user@fake.com", "user1pass")

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
