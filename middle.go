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
	"github.com/louisevanderlith/kong/tokens"
)

func InternalMiddleware(securer Security, name, secret string, handle http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tkn, err := GetBearerToken(r)

		if err != nil {
			log.Println("Get Bearer Token Error", err)
			http.Error(w, "", http.StatusUnauthorized)
			return
		}

		clms, err := securer.Inspect(tkn, name, secret)

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

func ClientMiddleware(clnt *http.Client, name, secret, securityUrl, authorityUrl string, handle http.HandlerFunc, scopes ...string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tkn, err := FetchToken(clnt, securityUrl, name, secret, scopes...)

		if err != nil {
			status, err := strconv.Atoi(err.Error())

			if err != nil {
				log.Println("Atoi Error", err)
				http.Error(w, "", http.StatusInternalServerError)
				return
			}

			if status == http.StatusUnprocessableEntity {
				cbUrl := fmt.Sprintf("https://%s/callback", r.Host)
				consntUrl := fmt.Sprintf("%s/consent?client=%s&callback=%s", authorityUrl, name, cbUrl)
				http.Redirect(w, r, consntUrl, http.StatusTemporaryRedirect)
				return
			}

			http.Error(w, "", status)
			return
		}

		claims, err := Exchange(http.DefaultClient, tkn, name, secret, securityUrl+"/info")

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

func ResourceMiddleware(clnt *http.Client, name, secret, securityUrl string, handle http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		token, err := GetBearerToken(r)

		if err != nil {
			log.Println("Get Bearer Token Error", err)
			http.Error(w, "", http.StatusUnauthorized)
			return
		}

		claims, err := Exchange(clnt, token, name, secret, securityUrl+"/inspect")

		if err != nil {
			log.Println("Exchange Error", err)
			http.Error(w, "", http.StatusUnauthorized)
			return
		}

		idn := context.WithValue(r.Context(), "claims", claims)

		r = r.WithContext(idn)
		handle(w, r)
	}
}

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
func FetchToken(clnt *http.Client, securityUrl, clientId, secret string, scopes ...string) (string, error) {
	tknReq := prime.TokenReq{
		UserToken: "",
		Scopes:    scopes,
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

//Exchange can be called by Clients, Resources & Users to obtain information from tokens.
//Clients use /info
//Resources use /inspect
//Users use /needs
func Exchange(clnt *http.Client, token, name, secret, inspectUrl string) (tokens.Claims, error) {
	insReq := prime.InspectReq{AccessCode: token}
	obj, err := json.Marshal(insReq)
	req, err := http.NewRequest(http.MethodPost, inspectUrl, bytes.NewBuffer(obj))
	req.SetBasicAuth(name, secret)

	if err != nil {
		return nil, err
	}

	resp, err := clnt.Do(req)

	if err != nil {
		return nil, err
	}

	defer resp.Body.Close()

	clms := tokens.EmptyClaims()
	dec := json.NewDecoder(resp.Body)
	err = dec.Decode(&clms)

	if err != nil {
		return nil, err
	}

	return clms, nil
}
