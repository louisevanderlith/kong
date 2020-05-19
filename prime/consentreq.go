package prime

import "github.com/louisevanderlith/kong/tokens"

type ConsentRequest struct {
	User   tokens.Claimer
	Claims []string
}
