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
	Insight(request prime.QueryRequest) (tokens.Claims, error)
}

//Security controls Client and Resource authentication
type Security interface {
	tokens.Signer
	IdentityInsider
	RequestToken(id, secret, ut string, resources map[string]bool) (tokens.Identity, error)
	ClientResourceQuery(clientId string) (map[string][]string, error)
	Whitelist(resource, secret string) ([]string, error)
}
