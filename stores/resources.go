package stores

import (
	"github.com/louisevanderlith/kong/prime"
)

type ResourceStore interface {
	GetResource(name string) (prime.Resource, error)
}
