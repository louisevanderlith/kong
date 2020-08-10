package kong

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"strconv"
	"strings"

	"github.com/louisevanderlith/kong/prime"
)

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

func ClientMiddleware(clnt *http.Client, id, secret, securityUrl, authorityUrl string, handle http.HandlerFunc, scopes map[string]bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tkn, err := FetchToken(clnt, securityUrl, id, secret, scopes)

		if err != nil {
			status, err := strconv.Atoi(err.Error())

			if err != nil {
				log.Println("Atoi Error", err)
				http.Error(w, "", http.StatusInternalServerError)
				return
			}

			if status == http.StatusUnprocessableEntity {
				cbUrl := fmt.Sprintf("https://%s/callback", r.Host)
				consntUrl := fmt.Sprintf("%s/consent?client=%s&callback=%s", authorityUrl, id, cbUrl)
				http.Redirect(w, r, consntUrl, http.StatusTemporaryRedirect)
				return
			}

			http.Error(w, "", status)
			return
		}

		claims, err := FetchIdentity(http.DefaultClient, []byte(tkn), securityUrl+"/info", id, secret)

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

//ResourceMiddleware
func ResourceMiddleware(clnt *http.Client, scope, secret, securityUrl, managerUrl string, handle http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		token, err := GetBearerToken(r)

		if err != nil {
			log.Println("Get Bearer Token Error", err)
			http.Error(w, "", http.StatusUnauthorized)
			return
		}

		claims, err := FetchIdentity(clnt, []byte(token), securityUrl+"/inspect", scope, secret)

		if err != nil {
			log.Println("Exchange Error", err)
			http.Error(w, "", http.StatusUnauthorized)
			return
		}

		idn := context.WithValue(r.Context(), "claims", claims)
		r = r.WithContext(idn)

		if claims.HasUser() && len(managerUrl) > 0 {
			usrclaims, err := FetchUserIdentity(clnt, []byte(claims.GetUserToken()), []byte(token), managerUrl)

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
func FetchToken(clnt *http.Client, securityUrl, clientId, secret string, scopes map[string]bool) (string, error) {
	tknReq := prime.QueryRequest{
		Token:  "",
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
