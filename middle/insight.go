package middle

import (
	"github.com/louisevanderlith/kong/prime"
	"github.com/louisevanderlith/kong/tokens"
)

//IdentityInsider provides the ability for Resources and Clients to inspect tokens
type IdentityInsider interface {
	ResourceInsight(token, resource, secret string) (tokens.Identity, error)
	ClientInsight(token, secret string) (tokens.Identity, error)
}

//UserInsider
type UserInsider interface {
	Insight(usertoken string) (tokens.Claims, error)
}

//Security controls Client and Resource authentication
type Security interface {
	tokens.Signer
	IdentityInsider
	RequestToken(id, secret, ut string, resources map[string]bool) (tokens.Identity, error)
	ClientResourceQuery(clientId string) (prime.ClaimConsent, error)
	Whitelist(resource, secret string) ([]string, error)
}
