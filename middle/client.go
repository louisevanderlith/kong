package middle

import (
	"context"
	"github.com/louisevanderlith/kong/prime"
	"github.com/louisevanderlith/kong/stores"
	"net/http"
	"strconv"
	"time"
)

type ClientWare interface {
	Intent(handle http.HandlerFunc, scopes map[string]bool) http.HandlerFunc
	Callback(w http.ResponseWriter, r *http.Request)
}

func NewClientMiddleware(svc stores.APPService) ClientWare {
	return cware{svc}
}

type cware struct {
	svc stores.APPService
}

func (cw cware) Intent(handle http.HandlerFunc, scopes map[string]bool) http.HandlerFunc {
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

		tknresp, err := cw.svc.RequestToken(tknreq)

		if err != nil {
			status, err := strconv.Atoi(err.Error())

			if err != nil {
				http.Error(w, "", http.StatusInternalServerError)
				return
			}

			if status == http.StatusUnprocessableEntity {
				cw.svc.SendToConsent(w, r, tknresp.Expires)
				return
			}

			http.Error(w, "", status)
			return
		}

		claims, err := cw.svc.FetchIdentity([]byte(tknresp.Token))

		if err != nil {
			http.Error(w, "", http.StatusUnauthorized)
			return
		}

		idn := context.WithValue(r.Context(), "claims", claims)
		tidn := context.WithValue(idn, "token", tknresp.Token)

		if claims.HasUser() {
			usrclaims, err := cw.svc.FetchUserIdentity([]byte(tknresp.Token))

			if err != nil {
				http.Error(w, "", http.StatusUnauthorized)
				return
			}

			uidn := context.WithValue(tidn, "userclaims", usrclaims)
			r = r.WithContext(uidn)
		} else {
			r = r.WithContext(tidn)
		}

		handle(w, r)
	}
}

func (cw cware) Callback(w http.ResponseWriter, r *http.Request) {
	oauthState, _ := r.Cookie("state")

	state := r.URL.Query()["state"]

	if state[0] != oauthState.Value {
		http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
		return
	}

	token := r.URL.Query()["token"]

	if len(token) == 0 {
		http.Error(w, "", http.StatusBadRequest)
		return
	}

	exp := r.URL.Query()["exp"]

	if len(exp) == 0 {
		http.Error(w, "", http.StatusBadRequest)
		return
	}

	exptime, err := time.Parse(time.StampMicro, exp[0])

	if err != nil {
		http.Error(w, "", http.StatusInternalServerError)
	}

	saveUserTokenCookie(w, token[0], exptime)

	http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
}

func saveUserTokenCookie(w http.ResponseWriter, usrToken string, expiration time.Time) {
	cookie := http.Cookie{Name: "user", Value: usrToken, Expires: expiration}
	http.SetCookie(w, &cookie)
}
