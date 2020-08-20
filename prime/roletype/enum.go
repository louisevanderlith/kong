package roletype

// Environment provides indicates in which environment a system is
type Enum int

const (
	Nobody Enum = iota
	User
	Owner
	Admin
)

var roletypes = [...]string{
	"Admin",
	"Owner",
	"User",
	"Nobody",
}

func (e Enum) String() string {
	return roletypes[e]
}
