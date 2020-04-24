package kong

type UserToken struct {
	Name   string
	Key    string
	Scopes []string //consented scopes
}

func (u UserToken) GetClaim(name string) string {
	switch name {
	case "username":
		return u.Name
	case "userkey":
		return u.Key
	}

	return ""
}
