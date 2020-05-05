package stores

type AuthStore interface {
	ProfileStore
	UserStore
	ResourceStore
}
