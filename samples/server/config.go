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

	ps := fakes.NewFakePS()
	us := fakes.NewFakeUS()
	rs := fakes.NewFakeRS()
	gob.Register(tokens.Claims{})
	stor := sessions.NewCookieStore(
		securecookie.GenerateRandomKey(64),
		securecookie.GenerateRandomKey(32),
	)
	stor.Options.Secure = true
	stor.Options.HttpOnly = true

	Author = kong.CreateAuthority(ps, us, rs, "", stor)
}
