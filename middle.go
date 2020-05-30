package kong

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/go-session/session"
	"io/ioutil"
	"log"
	"net/http"
	"strings"

	"github.com/louisevanderlith/kong/prime"
	"github.com/louisevanderlith/kong/tokens"
)

func InternalMiddleware(authr Author, name, secret string, handle http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		token, err := GetBearerToken(r)

		if err != nil {
			log.Println(err)
			w.WriteHeader(http.StatusUnauthorized)
			w.Write(nil)
			return
		}

		clms, err := authr.Inspect(token, name, secret)

		if err != nil {
			log.Println(err)
			w.WriteHeader(http.StatusUnauthorized)
			w.Write(nil)
			return
		}

		if err != nil {
			log.Println(err)
			w.WriteHeader(http.StatusUnauthorized)
			w.Write(nil)
			return
		}

		idn := context.WithValue(r.Context(), "claims", clms)

		r = r.WithContext(idn)
		handle(w, r)
	}
}

func ClientMiddleware(clnt *http.Client, name, secret, secureUrl, authUrl string, handle http.HandlerFunc, scopes ...string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		stor, err := session.Start(nil, w, r)

		if err != nil {
			log.Println(err)
			w.WriteHeader(http.StatusInternalServerError)
			w.Write(nil)
			return
		}

		tkn, ok := stor.Get("access.token")

		if !ok {
			tkn, err = FetchToken(clnt, secureUrl, name, secret, scopes...)

			if err != nil {
				log.Println(err)
				if err.Error() == "user login required" {
					cbUrl := fmt.Sprintf("https://%s/callback", r.Host)
					consntUrl := fmt.Sprintf("%s/consent?client=%s&callback=%s", authUrl, name, cbUrl)
					http.Redirect(w, r, consntUrl, http.StatusTemporaryRedirect)
					return
				}

				w.WriteHeader(http.StatusInternalServerError)
				w.Write(nil)
				return
			}
		}

		claims, err := Exchange(http.DefaultClient, tkn.(string), name, secret, secureUrl+"/info")

		if err != nil {
			log.Println(err)
			w.WriteHeader(http.StatusUnauthorized)
			w.Write(nil)
			return
		}

		idn := context.WithValue(r.Context(), "claims", claims)

		r = r.WithContext(idn)
		handle(w, r)
	}
}

func ResourceMiddleware(name, secret, authUrl string, handle http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		token, err := GetBearerToken(r)

		if err != nil {
			log.Println(err)
			w.WriteHeader(http.StatusUnauthorized)
			w.Write(nil)
			return
		}

		claims, err := Exchange(http.DefaultClient, token, name, secret, authUrl+"/inspect")

		if err != nil {
			log.Println(err)
			w.WriteHeader(http.StatusUnauthorized)
			w.Write(nil)
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

func FetchToken(clnt *http.Client, secureUrl, clientId, secret string, scopes ...string) (string, error) {
	tknReq := prime.TokenReq{
		UserToken: "",
		Scopes:    scopes,
	}
	obj, err := json.Marshal(tknReq)

	if err != nil {
		return "", err
	}

	req, err := http.NewRequest(http.MethodPost, secureUrl+"/token", bytes.NewBuffer(obj))
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

func Exchange(clnt *http.Client, token, name, secret, inspectUrl string) (tokens.Claimer, error) {
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

	var clms tokens.Claims
	dec := json.NewDecoder(resp.Body)
	err = dec.Decode(&clms)

	if err != nil {
		return nil, err
	}

	return clms, nil
}
