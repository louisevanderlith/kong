package stores

import "github.com/louisevanderlith/kong/prime"

type SecureStore interface {
	GetProfile(id string) (prime.Profile, error)
	GetProfileClient(id string) (prime.Profile, prime.Client, error)
	GetWhitelist(prefix string) []string
	GetResource(name string) (prime.Resource, error)
}
