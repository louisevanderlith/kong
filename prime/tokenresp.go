package prime

import "time"

type TokenResponse struct {
	Token   string
	Expires time.Time
}
