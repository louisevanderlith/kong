package kong

import (
	"bytes"
	"context"
	"encoding/json"
	"github.com/go-session/session"
	"log"
	"net/http"
	"strings"

	"github.com/louisevanderlith/kong/prime"
	"github.com/louisevanderlith/kong/tokens"
)

func ClientMiddleware(name, secret, authUrl string, handle http.HandlerFunc) http.HandlerFunc {
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
			log.Println(err)
			w.Header().Add("Location", authUrl + "/consent")
			w.WriteHeader(http.StatusFound)
			return
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
