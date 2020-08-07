package entity

import (
	"github.com/louisevanderlith/kong"
	"github.com/louisevanderlith/kong/fakes"
)

var Manager kong.Manager

func init() {
	//gob.Register(tokens.Claims)
	Manager = kong.NewManager(fakes.NewFakeUserStore())
}
