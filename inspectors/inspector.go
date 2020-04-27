package inspectors

type Inspector interface {
	Exchange(rawtoken, scope, secret string) (map[string]string, error)
}
