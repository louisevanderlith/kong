package secure

import (
	"encoding/json"
	"github.com/louisevanderlith/kong/prime"
	"github.com/louisevanderlith/kong/samples/servers/secure"
	"log"
	"net/http"
)

func HandleTokenPOST(w http.ResponseWriter, r *http.Request) {
	clnt, pass, ok := r.BasicAuth()

	if !ok {
		http.Error(w, "", http.StatusUnauthorized)
		return
	}

	dec := json.NewDecoder(r.Body)
	req := prime.TokenReq{}
	err := dec.Decode(&req)

	if err != nil {
		log.Println("Bind Error", err)
		http.Error(w, "", http.StatusBadRequest)
		return
	}

	tkn, err := secure.Security.RequestToken(clnt, pass, req.UserToken, req.Scopes...)

	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	stkn, err := secure.Security.Sign(tkn, 5)

	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Write([]byte(stkn))
}
