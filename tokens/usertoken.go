package tokens

type UserToken struct {
	Name   string
	Key    string
	Claims []string //consented claims
}

func (u UserToken) ClaimAllowed(claim string) bool {
	for _, v := range u.Claims {
		if v == claim {
			return true
		}
	}

	return false
}

func (u UserToken) Valid() bool {
	return len(u.Claims) > 0
}
