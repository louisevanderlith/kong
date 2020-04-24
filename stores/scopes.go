package stores

import "kong/scopes"

type ScopeStore interface {
	GetScope(name string) (scopes.Scoper, error)
}
