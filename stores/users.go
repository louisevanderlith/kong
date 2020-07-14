package stores

import "github.com/louisevanderlith/kong/prime"

type UserStore interface {
	GetUser(id string) prime.Userer
	GetUserByName(username string) (string, prime.Userer)
}
