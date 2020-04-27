package tokens

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"github.com/louisevanderlith/kong/prime"
	"strings"
	"time"
)

type Accessor interface {
	GetClient() string
	HasClaim(claim string) bool
	GetClaim(claim string) string
	GetScopeClaims(scope string) map[string]string
	AssignResourceClaims(resrc prime.Resource) map[string]string
	Encode(pubkey *rsa.PublicKey) ([]byte, error)
}

type AccessToken struct {
	Client     string
	FullClaims map[string]string //scope.claim
}

func (a AccessToken) GetClient() string {
	return a.Client
}

func (a AccessToken) HasClaim(claim string) bool {
	_, ok := a.FullClaims[claim]
	return ok
}

func (a AccessToken) GetClaim(claim string) string {
	val, ok := a.FullClaims[claim]

	if !ok {
		return ""
	}

	return val
}

func (a AccessToken) GetScopeClaims(scope string) map[string]string {
	result := make(map[string]string)

	for k, v := range a.FullClaims {
		if strings.HasPrefix(k, scope) {
			result[k] = v
		}
	}

	return result
}

func (a AccessToken) AssignResourceClaims(resrc prime.Resource) map[string]string {
	result := a.spawnClaims()

	for _, c := range resrc.Claims {
		ok := a.HasClaim(c)
		if ok {
			result[c] = a.GetClaim(c)
		}
	}

	return result
}

func (a AccessToken) spawnClaims() map[string]string {
	result := make(map[string]string)
	result["kong.info.client"] = a.Client
	result["kong.info.iat"] = time.Now().String()
	result["kong.info.exp"] = time.Now().Add(time.Minute * 3).String()

	return result
}

func (a AccessToken) Encode(pubkey *rsa.PublicKey) ([]byte, error) {
	bits, err := json.Marshal(a)

	if err != nil {
		return nil, err
	}

	ciphertxt, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, pubkey, bits, []byte("access"))

	if err != nil {
		return nil, err
	}

	val := hex.EncodeToString(ciphertxt)

	return []byte(val), nil
}
