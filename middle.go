package kong

import (
	"context"
	"github.com/louisevanderlith/kong/inspectors"
	"log"
	"net/http"
	"strings"
)

func ResourceMiddleware(scope, secret string, handle http.HandlerFunc, ins inspectors.Inspector) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		reqToken := r.Header.Get("Authorization")

		if len(reqToken) == 0 {
			w.WriteHeader(http.StatusUnauthorized)
			w.Write(nil)
			return
		}

		prefix := "Bearer "

		if !strings.HasPrefix(reqToken, prefix) {
			w.WriteHeader(http.StatusUnauthorized)
			w.Write(nil)
			return
		}
		token := reqToken[len(prefix):]

		if len(token) == 0 {
			w.WriteHeader(http.StatusUnauthorized)
			w.Write(nil)
			return
		}

		claims, err := ins.Exchange(token, scope, secret)

		if err != nil {
			log.Println(err)
			w.WriteHeader(http.StatusUnauthorized)
			w.Write(nil)
			return
		}

		context.WithValue(r.Context(), "claims", claims)
		handle(w, r)
	}
}
