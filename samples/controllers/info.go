package controllers

import (
	"encoding/json"
	"github.com/louisevanderlith/kong/prime"
	"github.com/louisevanderlith/kong/samples/server"
	"log"
	"net/http"
)

func HandleInfoPOST(w http.ResponseWriter, r *http.Request) {
	clntId, pass, ok := r.BasicAuth()

	if !ok {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write(nil)
		return
	}

	dec := json.NewDecoder(r.Body)
	req := prime.InspectReq{}
	err := dec.Decode(&req)

	if err != nil {
		log.Println(err)
		w.WriteHeader(http.StatusBadRequest)
		w.Write(nil)
		return
	}

	claims, err := server.Author.Info(req.AccessCode, clntId, pass)

	if err != nil {
		log.Println(err)
		w.WriteHeader(http.StatusBadRequest)
		w.Write(nil)
		return
	}

	bits, err := json.Marshal(claims)

	if err != nil {
		log.Println(err)
		w.WriteHeader(http.StatusInternalServerError)
		w.Write(nil)
		return
	}

	w.Write(bits)
}

