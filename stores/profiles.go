package stores

import (
	"github.com/louisevanderlith/kong/prime"
)

type ProfileStore interface {
	GetProfile(id string) (prime.Profile, error)
	GetProfileClient(id string) (prime.Profile, prime.Client, error)
	GetWhitelist() []string
}
