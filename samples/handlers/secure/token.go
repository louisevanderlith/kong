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
	req := prime.QueryRequest{}
	err := dec.Decode(&req)

	if err != nil {
		log.Println("Bind Error", err)
		http.Error(w, "", http.StatusBadRequest)
		return
	}

	require, err := req.GetRequirements()

	if err != nil {
		log.Println("Get Requirements Error", err)
		http.Error(w, "", http.StatusBadRequest)
		return
	}

	tkn, err := secure.Security.RequestToken(clnt, pass, req.Token, require)

	if err != nil {
		log.Println("Request Token Error", err)
		http.Error(w, "", http.StatusUnprocessableEntity)
		return
	}

	stkn, err := secure.Security.Sign(tkn, 5)

	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	_, err = w.Write([]byte(stkn))

	if err != nil {
		log.Println("Serve Error", err)
	}
}
