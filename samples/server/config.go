package server

import (
	"github.com/louisevanderlith/kong"
	"github.com/louisevanderlith/kong/fakes"
	"github.com/louisevanderlith/kong/signing"
)

var Author = kong.Authority{
	Profiles: fakes.NewFakePS(),
	Users:    fakes.NewFakeUS(),
	Resources:   fakes.NewFakeRS(),
}

func init() {
	crt, err := signing.Initialize("/", false)

	if err != nil {
		panic(err)
	}

	Author.SignCert = crt
}
