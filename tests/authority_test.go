package tests

import (
	"github.com/louisevanderlith/kong"
	"github.com/louisevanderlith/kong/fakes"
)

//Test files are created for every interface method
var authr kong.Author

func init() {
	a, err := kong.CreateAuthority(fakes.NewFakeStore())

	if err != nil {
		panic(err)
	}

	authr = a
}
