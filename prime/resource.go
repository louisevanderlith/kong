package prime

type Resource struct {
	Name        string
	DisplayName string
	Secret      string
	Claims      []string
}

func (r Resource) VerifySecret(secret string) bool {
	return r.Secret == secret
}
