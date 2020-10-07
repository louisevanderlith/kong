package middle

import (
	"context"
	"github.com/louisevanderlith/kong/prime"
	"github.com/louisevanderlith/kong/stores"
	"log"
	"net/http"
	"strconv"
)

type Ware interface {
	Intent(handlerFunc http.HandlerFunc, scope map[string]bool) http.HandlerFunc
}

func NewMiddleware(svc stores.APPService) Ware {
	return ware{svc: svc}
}

type ware struct {
	svc stores.APPService
}

func (mw ware) Intent(handle http.HandlerFunc, scopes map[string]bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		authCookie, _ := r.Cookie("user")
		usrToken := ""

		if authCookie != nil {
			usrToken = authCookie.Value
		}

		tknreq := prime.TokenRequest{
			UserToken: usrToken,
			Scopes:    scopes,
		}

		tknresp, err := mw.svc.RequestToken(tknreq)

		if err != nil {
			status, err := strconv.Atoi(err.Error())

			if err != nil {
				http.Error(w, "", http.StatusInternalServerError)
				return
			}

			if status == http.StatusUnprocessableEntity {

				mw.svc.SendToConsent(w, r, tknresp.Expires)
				return
			}

			http.Error(w, "", status)
			return
		}

		handle.ServeHTTP(w, r)
	}
}

//BearerToken will read Authorization Header and apply the token to the context
func (mw ware) BearerToken(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token, err := GetBearerToken(r)

		if err != nil {
			log.Println("Get Bearer Token Error", err)
			http.Error(w, "", http.StatusUnauthorized)
			return
		}

		idn := context.WithValue(r.Context(), "token", token)
		next.ServeHTTP(w, r.WithContext(idn))
	})
}

func (mw ware) Identity(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		token := GetToken(r)

		if len(token) == 0 {
			log.Println("No Token in Context")
			http.Error(w, "", http.StatusUnauthorized)
			return
		}

		claims, err := mw.svc.FetchIdentity([]byte(token))

		if err != nil {
			log.Println("Exchange Error", err)
			http.Error(w, "", http.StatusUnauthorized)
			return
		}

		idn := context.WithValue(r.Context(), "claims", claims)

		next.ServeHTTP(w, r.WithContext(idn))
	}
}

func (mw ware) UserIdentity(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		token := GetToken(r)

		if len(token) == 0 {
			log.Println("No Token in Context")
			http.Error(w, "", http.StatusUnauthorized)
			return
		}

		claims := GetIdentity(r)

		if claims == nil {
			log.Println("No Claims in Context")
			http.Error(w, "", http.StatusUnauthorized)
			return
		}

		if claims.HasUser() {
			usrclaims, err := mw.svc.FetchUserIdentity([]byte(token))

			if err != nil {
				log.Println("User Exchange Error", err)
				http.Error(w, "", http.StatusUnauthorized)
			}

			idn := context.WithValue(r.Context(), "userclaims", usrclaims)
			next.ServeHTTP(w, r.WithContext(idn))
		}
	}
}
