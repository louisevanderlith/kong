package middle

import (
	"context"
	"log"
	"net/http"
)

//InternalMiddleware is used by Security Manager, since there is no need to call an API
func InternalMiddleware(securer Security, scope, secret string, handle http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tkn, err := GetBearerToken(r)

		if err != nil {
			log.Println("Get Bearer Token Error", err)
			http.Error(w, "", http.StatusUnauthorized)
			return
		}

		clms, err := securer.ResourceInsight(tkn, scope, secret)

		if err != nil {
			log.Println("Inspect Error", err)
			http.Error(w, "", http.StatusUnauthorized)
			return
		}

		idn := context.WithValue(r.Context(), "claims", clms)
		tidn := context.WithValue(idn, "token", tkn)

		r = r.WithContext(tidn)
		handle(w, r)
	}
}
