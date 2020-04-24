package scopes

//Known provides claims
type Known struct {
	Name string
	DisplayName string
	Secret string
	Claims []string
}

func (k Known) GetClaims() []string {
	return k.Claims
}

func (k Known) GetName() string {
	return k.Name
}

func (k Known) VerifySecret(s string) bool {
	return k.Secret == s
}