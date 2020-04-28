package controllers

import (
	"encoding/json"
	"log"
	"net/http"

	"github.com/louisevanderlith/kong/samples/models"
	"github.com/louisevanderlith/kong/samples/server"
)

func HandleTokenPOST(w http.ResponseWriter, r *http.Request) {
	clnt, pass, ok := r.BasicAuth()

	if !ok {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write(nil)
		return
	}

	dec := json.NewDecoder(r.Body)
	req := models.TokenReq{}
	err := dec.Decode(&req)

	if err != nil {
		log.Println(err)
		w.WriteHeader(http.StatusBadRequest)
		w.Write(nil)
		return
	}

	tkn, err := server.Author.RequestToken(clnt, pass, req.UserToken, req.Scope)

	if err != nil {
		log.Println(err)
		w.WriteHeader(http.StatusUnauthorized)
		w.Write(nil)
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Write(tkn)
}
