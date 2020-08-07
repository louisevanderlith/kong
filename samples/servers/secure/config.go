package secure

import (
	"github.com/louisevanderlith/kong"
	"github.com/louisevanderlith/kong/fakes"
)

var Security kong.Security

func init() {
	//gob.Register(tokens.Claims)

	s, err := kong.CreateSecurity(fakes.NewFakeStore())

	if err != nil {
		panic(err)
	}

	Security = s
}
