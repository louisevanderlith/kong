package kong

import (
	"bytes"
	"context"
	"encoding/json"
	"github.com/louisevanderlith/kong/prime"
	"github.com/louisevanderlith/kong/tokens"
	"log"
	"net/http"
	"strings"
)

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
