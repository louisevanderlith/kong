package core

import (
	"github.com/louisevanderlith/kong/tokens"
)

//IdentityInsider provides the ability for Resources and Clients to inspect tokens
type IdentityInsider interface {
	ResourceInsight(token, resource, secret string) (tokens.Identity, error)
	ClientInsight(token, secret string) (tokens.Identity, error)
}

//UserInsider
type UserInsider interface {
	Insight(usertoken string) (tokens.UserIdentity, error)
}
