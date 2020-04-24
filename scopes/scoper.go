package scopes

//Scoper can be a scope that either requests or allows
type Scoper interface {
	GetName() string
	GetClaims() []string
	VerifySecret(s string) bool
}
