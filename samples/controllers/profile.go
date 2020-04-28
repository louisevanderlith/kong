package controllers

import (
	"encoding/json"
	"log"
	"net/http"
)

//Example of a scope that doesn't require user login
func HandleProfileGET(w http.ResponseWriter, r *http.Request) {
	claims := r.Context().Value("claims")

	if claims == nil {
		w.WriteHeader(http.StatusUnauthorized)
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

	w.WriteHeader(http.StatusOK)
	w.Write(bits)
}
