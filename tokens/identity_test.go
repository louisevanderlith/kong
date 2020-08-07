package tokens

import "testing"

func TestNewIdentity_Valid_NoError(t *testing.T) {
	_, err := NewIdentity("kong.viewr")

	if err != nil {
		t.Error(err)
	}
}

func TestNewIdentity_Invalid_Error(t *testing.T) {
	_, err := NewIdentity("donkey")

	if err == nil {
		t.Error("unexpected success")
	}
}

func TestNewIdentity_HasID(t *testing.T) {
	id := "kong.viewr"
	idn, err := NewIdentity(id)

	if err != nil {
		t.Error(err)
		return
	}

	if idn.GetID() != id {
		t.Error("expected", id, "got", idn.GetID())
	}
}

func TestNewIdentity_HasProfile(t *testing.T) {
	id := "kong.viewr"
	idn, err := NewIdentity(id)

	if err != nil {
		t.Error(err)
		return
	}

	exp := "kong"
	if idn.GetProfile() != exp {
		t.Error("expected", exp, "got", idn.GetProfile())
	}
}

func TestNewIdentity_HasClient(t *testing.T) {
	id := "kong.viewr"
	idn, err := NewIdentity(id)

	if err != nil {
		t.Error(err)
		return
	}

	exp := "viewr"
	if idn.GetClient() != exp {
		t.Error("expected", exp, "got", idn.GetClient())
	}
}
