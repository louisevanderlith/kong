package prime

type TokenRequest struct {
	UserToken string
	Scopes    map[string]bool
}
