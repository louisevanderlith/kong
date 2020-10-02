package middle

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"net/http"
	"strconv"
	"time"
)

type ClientInspector struct {
	id           string
	secret       string
	clnt         *http.Client
	securityUrl  string
	authorityUrl string
}

func NewClientInspector(id, secret string, clnt *http.Client, securityUrl, authorityUrl string) ClientInspector {
	return ClientInspector{
		id:           id,
		secret:       secret,
		clnt:         clnt,
		securityUrl:  securityUrl,
		authorityUrl: authorityUrl,
	}
}

func (ci ClientInspector) Middleware(handle http.HandlerFunc, scopes map[string]bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		authCookie, _ := r.Cookie("user")
		usrToken := ""

		if authCookie != nil {
			usrToken = authCookie.Value
		}

		tkn, err := FetchToken(ci.clnt, ci.securityUrl, ci.id, ci.secret, usrToken, scopes)

		if err != nil {
			status, err := strconv.Atoi(err.Error())

			if err != nil {
				http.Error(w, "", http.StatusInternalServerError)
				return
			}

			if status == http.StatusUnprocessableEntity {
				cbUrl := fmt.Sprintf("https://%s/callback", r.Host)
				state := generateStateOauthCookie(w)
				consntUrl := fmt.Sprintf("%s/consent?state=%s&client=%s&callback=%s", ci.authorityUrl, state, ci.id, cbUrl)
				http.Redirect(w, r, consntUrl, http.StatusTemporaryRedirect)
				return
			}

			http.Error(w, "", status)
			return
		}

		claims, err := FetchIdentity(http.DefaultClient, []byte(tkn), ci.securityUrl+"/info", ci.id, ci.secret)

		if err != nil {
			http.Error(w, "", http.StatusUnauthorized)
			return
		}

		idn := context.WithValue(r.Context(), "claims", claims)
		tidn := context.WithValue(idn, "token", tkn)

		r = r.WithContext(tidn)
		handle(w, r)
	}
}

func (ci ClientInspector) Callback(w http.ResponseWriter, r *http.Request) {
	oauthState, _ := r.Cookie("state")

	state := r.URL.Query()["state"]

	if state[0] != oauthState.Value {
		http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
		return
	}

	token := r.URL.Query()["token"]
	saveUserTokenCookie(w, token[0])

	http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
}

func saveUserTokenCookie(w http.ResponseWriter, usrToken string) {
	var expiration = time.Now().Add(1 * time.Hour)

	cookie := http.Cookie{Name: "user", Value: usrToken, Expires: expiration}
	http.SetCookie(w, &cookie)
}

func generateStateOauthCookie(w http.ResponseWriter) string {
	var expiration = time.Now().Add(1 * time.Hour)

	b := make([]byte, 16)
	rand.Read(b)
	state := base64.URLEncoding.EncodeToString(b)
	cookie := http.Cookie{Name: "state", Value: state, Expires: expiration}
	http.SetCookie(w, &cookie)

	return state
}
