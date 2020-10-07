package middle

import (
	"errors"
	"github.com/louisevanderlith/kong/tokens"
	"net/http"
	"strings"
)

//GetBearerToken returns the Bearer Authorization header
func GetBearerToken(r *http.Request) (string, error) {
	reqToken := r.Header.Get("Authorization")

	if len(reqToken) == 0 {
		return "", errors.New("header length invalid")
	}

	prefix := "Bearer "

	if !strings.HasPrefix(reqToken, prefix) {
		return "", errors.New("bearer not found")
	}

	token := reqToken[len(prefix):]

	if len(token) == 0 {
		return "", errors.New("token length invalid")
	}

	return token, nil
}

func GetScopes(r *http.Request) map[string]bool {
	v := r.Context().Value("scope")
	return v.(map[string]bool)
}

//GetToken will return 'token' assigned to Context
func GetToken(r *http.Request) string {
	v := r.Context().Value("token")

	return v.(string)
}

func GetIdentity(r *http.Request) tokens.Identity {
	val := r.Context().Value("claims")

	res, ok := val.(tokens.Identity)

	if !ok {
		return nil
	}

	return res
}

func GetUserIdentity(r *http.Request) tokens.UserIdentity {
	val := r.Context().Value("userclaims")

	res, ok := val.(tokens.UserIdentity)

	if !ok {
		return nil
	}

	return res
}
