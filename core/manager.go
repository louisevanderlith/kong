package core

import (
	"github.com/louisevanderlith/kong/prime"
	"github.com/louisevanderlith/kong/tokens"
)

//Security controls Client and Resource authentication
type SecurityManager interface {
	tokens.Signer
	IdentityInsider
	RequestToken(id, secret, ut string, resources map[string]bool) (tokens.Identity, error)
	ClientResourceQuery(clientId string) (prime.ClaimConsent, error)
	Whitelist(resource, secret string) ([]string, error)
}

//EntityManager controls User authentication and consent
type EntityManager interface {
	tokens.Signer
	UserInsider
	Login(id, username, password string) (tokens.UserIdentity, error)              //partial token
	Consent(usrToken string, consent map[string]bool) (tokens.UserIdentity, error) //finalize token
	FetchNeeds(usrToken string, needs ...string) (tokens.UserIdentity, error)
}

// AuthorityManager provides functions for connecting Security & User Manager functions
type AuthorityManager interface {
	ClientQuery(client string) (prime.ClaimConsent, error)
	GiveConsent(request prime.QueryRequest) (string, error)
	AuthenticateUser(request prime.LoginRequest) (string, error)
}
