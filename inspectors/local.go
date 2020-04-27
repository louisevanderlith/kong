package inspectors

import (
	"crypto/rsa"
	"errors"
	"github.com/louisevanderlith/kong/signing"
	"github.com/louisevanderlith/kong/stores"
)

type localInspector struct {
	privKey   *rsa.PrivateKey
	resources stores.ResourceStore
}

func NewLocalInspector(privKey *rsa.PrivateKey, rs stores.ResourceStore) Inspector {
	return localInspector{privKey: privKey, resources: rs}
}

func (i localInspector) Exchange(rawtoken, scope, secret string) (map[string]string, error) {
	resrc, err := i.resources.GetResource(scope)

	if err != nil {
		return nil, err
	}

	if !resrc.VerifySecret(secret) {
		return nil, errors.New("invalid secret")
	}

	accs, err := signing.DecodeToken(rawtoken, i.privKey)

	if err != nil {
		return nil, err
	}

	return accs.AssignResourceClaims(resrc), nil
}
