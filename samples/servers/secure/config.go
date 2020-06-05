package secure

import (
	"encoding/gob"
	"github.com/louisevanderlith/kong"
	"github.com/louisevanderlith/kong/fakes"
	"github.com/louisevanderlith/kong/tokens"
)

var Author kong.Author

func init() {
	gob.Register(tokens.Claims{})

	a, err := kong.CreateAuthority(fakes.NewFakeStore())

	if err != nil {
		panic(err)
	}

	Author = a
}
