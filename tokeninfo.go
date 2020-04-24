package kong

type TokenInfo struct {
	Valid bool
	Claims map[string]string
}
