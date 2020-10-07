package middle

import (
	"context"
	"github.com/louisevanderlith/kong/stores"
	"log"
	"net/http"
)

type ResourceWare interface {
	Lock(scope, secret string, handle http.HandlerFunc) http.HandlerFunc
}

func NewResourceInspector(svc stores.APIService) ResourceWare {
	return rware{
		svc: svc,
	}
}

type rware struct {
	svc stores.APIService
}

//ResourceMiddleware
func (rw rware) Lock(scope, secret string, handle http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		token, err := GetBearerToken(r)

		if err != nil {
			log.Println("Get Bearer Token Error", err)
			http.Error(w, "", http.StatusUnauthorized)
			return
		}

		claims, err := rw.svc.InspectIdentity(scope, secret, []byte(token))

		if err != nil {
			log.Println("Exchange Error", err)
			http.Error(w, "", http.StatusUnauthorized)
			return
		}

		idn := context.WithValue(r.Context(), "claims", claims)
		r = r.WithContext(idn)

		if claims.HasUser() {
			usrclaims, err := rw.svc.FetchUserIdentity([]byte(token))

			if err != nil {
				log.Println("User Exchange Error", err)
				http.Error(w, "", http.StatusUnauthorized)
			}

			idn := context.WithValue(r.Context(), "userclaims", usrclaims)
			r = r.WithContext(idn)
		}

		handle.ServeHTTP(w, r)
	}
}
