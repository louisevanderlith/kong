package prime

type ConsentRequest struct {
	UserToken   string
	Claims map[string]bool
}
