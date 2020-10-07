package securitymanager

import (
	"errors"
	"github.com/louisevanderlith/kong/stores"
	"github.com/louisevanderlith/kong/tokens"
)

type InternalInspector struct {
	scope  string
	secret string
}

func NewInternalInspector(scope, secret string) InternalInspector {
	return InternalInspector{
		scope:  scope,
		secret: secret,
	}
}

func NewSecureAPIService() stores.APIService {
	return intsvc{}
}

type intsvc struct {
}

//InspectIdentity returns the Full token identity
func (c intsvc) InspectIdentity(scope, secret string, token []byte) (tokens.Identity, error) {
	return _security.ResourceInsight(string(token), scope, secret)
}

//FetchUserIdentity return the User token identity
func (c intsvc) FetchUserIdentity(token []byte) (tokens.UserIdentity, error) {
	return nil, errors.New("not supported")
}

//Whitelist calls the Security whitelist endpoint to obtain a list of allowed Clients
func (c intsvc) Whitelist(scope, secret string) ([]string, error) {
	return _security.Whitelist(scope, secret)
}
