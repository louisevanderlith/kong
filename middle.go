package kong

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/go-session/session"
	"github.com/louisevanderlith/kong/samples/models"
	"io/ioutil"
	"log"
	"net/http"
	"strings"

	"github.com/louisevanderlith/kong/prime"
	"github.com/louisevanderlith/kong/tokens"
)

func ClientMiddleware(clnt *http.Client, name, secret, authUrl string, handle http.HandlerFunc, scopes ...string) http.HandlerFunc {
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
			tkn, err = FetchToken(clnt, authUrl, name, secret, scopes...)

			if err != nil {
				log.Println(err)
				w.WriteHeader(http.StatusInternalServerError)
				w.Write(nil)
				return
			}
		}

		claims, err := Exchange(tkn.(string), name, secret, authUrl+"/info")

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

func ResourceMiddleware(name, secret, authUrl string, handle http.HandlerFunc) http.HandlerFunc {
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

		claims, err := Exchange(token, name, secret, authUrl+"/inspect")

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

func FetchToken(clnt *http.Client, authUrl, clientId, secret string, scopes ...string) (string, error) {
	tknReq := models.TokenReq{
		UserToken: make(tokens.Claims),
		Scopes:    scopes,
	}
	obj, err := json.Marshal(tknReq)

	if err != nil {
		return "", err
	}

	req, err := http.NewRequest(http.MethodPost, authUrl+"/token", bytes.NewBuffer(obj))
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

func Exchange(token, name, secret, inspectUrl string) (tokens.Claimer, error) {
	insReq := prime.InspectReq{AccessCode: token}
	obj, err := json.Marshal(insReq)
	req, err := http.NewRequest(http.MethodPost, inspectUrl, bytes.NewBuffer(obj))
	req.SetBasicAuth(name, secret)

	if err != nil {
		return nil, err
	}

	defer req.Body.Close()

	var clms tokens.Claims
	dec := json.NewDecoder(req.Body)
	err = dec.Decode(&clms)

	if err != nil {
		return nil, err
	}

	return clms, nil
}
