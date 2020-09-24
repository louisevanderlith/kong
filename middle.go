package kong

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/louisevanderlith/kong/prime"
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
		authCookie, _ := r.Cookie("auth")
		usrToken := ""

		if authCookie != nil {
			usrToken = authCookie.Value
		}

		tkn, err := FetchToken(ci.clnt, ci.securityUrl, ci.id, ci.secret, usrToken, scopes)

		if err != nil {
			status, err := strconv.Atoi(err.Error())

			if err != nil {
				log.Println("Conversion Error", err)
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
			log.Println("Exchange Error", err)
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

type ResourceInspector struct {
	clnt        *http.Client
	securityUrl string
	managerUrl  string
}

func NewResourceInspector(clnt *http.Client, securityUrl, managerUrl string) ResourceInspector {
	return ResourceInspector{
		clnt:        clnt,
		securityUrl: securityUrl,
		managerUrl:  managerUrl,
	}
}

//ResourceMiddleware
func (ins ResourceInspector) Middleware(scope, secret string, handle http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		token, err := GetBearerToken(r)

		if err != nil {
			log.Println("Get Bearer Token Error", err)
			http.Error(w, "", http.StatusUnauthorized)
			return
		}

		claims, err := FetchIdentity(ins.clnt, []byte(token), ins.securityUrl+"/inspect", scope, secret)

		if err != nil {
			log.Println("Exchange Error", err)
			http.Error(w, "", http.StatusUnauthorized)
			return
		}

		idn := context.WithValue(r.Context(), "claims", claims)
		r = r.WithContext(idn)

		if claims.HasUser() && len(ins.managerUrl) > 0 {
			usrclaims, err := FetchUserIdentity(ins.clnt, []byte(claims.GetUserToken()), []byte(token), ins.managerUrl)

			if err != nil {
				log.Println("User Exchange Error", err)
				http.Error(w, "", http.StatusUnauthorized)
			}

			idn := context.WithValue(r.Context(), "userclaims", usrclaims)
			r = r.WithContext(idn)
		}

		handle(w, r)
	}
}

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

//FetchToken calls the Security Token endpoint to obtain a Client Token
func FetchToken(clnt *http.Client, securityUrl, clientId, secret, userToken string, scopes map[string]bool) (string, error) {
	tknReq := prime.QueryRequest{
		Token:  userToken,
		Claims: scopes,
	}
	obj, err := json.Marshal(tknReq)

	if err != nil {
		return "", err
	}

	req, err := http.NewRequest(http.MethodPost, securityUrl+"/token", bytes.NewBuffer(obj))
	req.SetBasicAuth(clientId, secret)

	if err != nil {
		return "", err
	}

	resp, err := clnt.Do(req)

	if err != nil {
		return "", err
	}

	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("%v", resp.StatusCode)
	}

	body, err := ioutil.ReadAll(resp.Body)
	if len(body) == 0 {
		return "", errors.New("no response")
	}

	return string(body), nil
}

//Whitelist calls the Security whitelist endpoint to obtain a list of allowed Clients
func Whitelist(clnt *http.Client, securityUrl, name, secret string) ([]string, error) {
	req, err := http.NewRequest(http.MethodGet, securityUrl+"/whitelist", nil)
	req.SetBasicAuth(name, secret)

	if err != nil {
		return nil, err
	}

	resp, err := clnt.Do(req)

	if err != nil {
		return nil, err
	}

	defer resp.Body.Close()

	var wht []string
	dec := json.NewDecoder(resp.Body)
	err = dec.Decode(&wht)

	if err != nil {
		return nil, err
	}

	return wht, nil
}
