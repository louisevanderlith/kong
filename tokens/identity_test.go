package tokens

import (
	"github.com/louisevanderlith/kong/dict"
	"testing"
)

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

func TestIdentity_GetCode(t *testing.T) {
	clmr,err := NewIdentity("kong.test")

	if err != nil {
		t.Error("New Identity Error", err)
		return
	}

	clmr.AddClaim("user", "donkey")

	codes := dict.Map{
		dict.KeyValue{
			Key:   "tagx",
			Value: "00-XXXX",
		},
	}

	err = clmr.AddClaim(KongCodes, codes)

	if err != nil {
		t.Error("Add Codes Error", err)
		return
	}

	val, err := clmr.GetCode("tagx")

	if err != nil {
		t.Error("Get Code Error", err)
		return
	}

	if val != "00-XXXX" {
		t.Error("invalid claim value", val)
	}
}
