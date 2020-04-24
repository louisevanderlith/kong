package scopes

//resources request claims
type Resource struct {
	Name        string
	DisplayName string
	Secret      string
	Claims      []string
}

func (r Resource) GetClaims() []string {
	return r.Claims
}

func (r Resource) GetName() string {
	return r.Name
}

func (r Resource) VerifySecret(s string) bool {
	return r.Secret == s
}
