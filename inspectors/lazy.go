package inspectors

import (
	"crypto/rsa"
	"github.com/louisevanderlith/kong/prime"
	"github.com/louisevanderlith/kong/signing"
	"github.com/louisevanderlith/kong/tokens"
)

type lazyInspector struct {
	privKey *rsa.PrivateKey
}

func NewLazyInspector(privKey *rsa.PrivateKey) Inspector {
	return lazyInspector{privKey}
}

func (i lazyInspector) Exchange(rawtoken, scope, secret string) (map[string]string, error) {
	accs, err := signing.DecodeToken(rawtoken, i.privKey)

	if err != nil {
		return nil, err
	}

	return accs.(tokens.AccessToken).AssignResourceClaims(prime.Resource{}), nil
}
