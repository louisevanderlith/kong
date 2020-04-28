package tests

import (
	"github.com/louisevanderlith/kong/tokens"
	"testing"
)

func TestClaimer_AddClaim_New(t *testing.T) {
	clmr := make(tokens.Claims)
	err := clmr.AddClaim("user", "donkey")

	if err != nil {
		t.Error(err)
	}
}

func TestClaimer_AddClaim_Exists(t *testing.T) {
	clmr := make(tokens.Claims)
	clmr.AddClaim("user", "donkey")
	err := clmr.AddClaim("user", "kong")

	if err == nil {
		t.Error("able to add multiple keys")
	}
}
