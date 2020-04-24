package kong

type Accessor interface {
	GetClient() string
	HasClaim(claim string) bool
	GetClaim(claim string) string
}

type AccessToken struct {
	Client string
	Scopes []string
	Claims map[string]string
}

func (a AccessToken) GetClient() string {
	return a.Client
}

func (a AccessToken) HasClaim(claim string) bool {
	_, ok := a.Claims[claim]

	return ok
}

func (a AccessToken) GetClaim(claim string) string {
	val, ok := a.Claims[claim]

	if !ok {
		return ""
	}

	return val
}