package prime

import (
	"github.com/louisevanderlith/kong/tokens"
)

type TokenReq struct {
	UserToken tokens.Claims
	Scopes    []string
}
