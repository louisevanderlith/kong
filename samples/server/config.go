package server

import (
	"encoding/gob"
	"github.com/gorilla/securecookie"
	"github.com/gorilla/sessions"
	"github.com/louisevanderlith/kong"
	"github.com/louisevanderlith/kong/fakes"
	"github.com/louisevanderlith/kong/tokens"
)

var Author kong.Authority

func init() {
	crt, err := kong.InitializeCert("/", false)

	if err != nil {
		panic(err)
	}

	Author = kong.Authority{
		Profiles:  fakes.NewFakePS(),
		Users:     fakes.NewFakeUS(),
		Resources: fakes.NewFakeRS(),
	}

	Author.SignCert = crt

	authKeyOne := securecookie.GenerateRandomKey(64)
	encryptionKeyOne := securecookie.GenerateRandomKey(32)
	gob.Register(tokens.Claims{})
	stor := sessions.NewCookieStore(
		authKeyOne,
		encryptionKeyOne,
	)
	stor.Options.Secure = true
	stor.Options.HttpOnly = true

	Author.Cookies = stor
}
