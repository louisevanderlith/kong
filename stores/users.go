package stores

import "github.com/louisevanderlith/kong/prime"

type UserStore interface {
	GetUser(id string) prime.User
	GetUserByName(username string) (string, prime.User)
}
