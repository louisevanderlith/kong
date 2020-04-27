package tests

import (
	"github.com/louisevanderlith/kong"
	"testing"
)

func TestClaimer_AddClaim_New(t *testing.T) {
	clmr := kong.NewClaimer()
	err := clmr.AddClaim("user", "donkey")

	if err != nil {
		t.Error(err)
	}
}

func TestClaimer_AddClaim_Exists(t *testing.T) {
	clmr := kong.NewClaimer()
	clmr.AddClaim("user", "donkey")
	err := clmr.AddClaim("user", "kong")

	if err == nil {
		t.Error("able to add multiple keys")
	}
}
