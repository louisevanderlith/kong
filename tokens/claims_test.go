package tokens

import "testing"

func TestClaims_AddClaim_New(t *testing.T) {
	clmr := EmptyClaims()
	err := clmr.AddClaim("user", "donkey")

	if err != nil {
		t.Error(err)
	}

	if !clmr.HasClaim("user") {
		t.Error("claim not found")
	}
}

func TestClaims_AddClaim_NoDuplicates(t *testing.T) {
	clmr := EmptyClaims()
	clmr.AddClaim("user", "donkey")
	err := clmr.AddClaim("user", "kong")

	if err == nil {
		t.Error("able to add multiple keys")
	}

	val := clmr.GetClaimString("user")

	if val != "donkey" {
		t.Error("invalid claim value", val)
	}
}
