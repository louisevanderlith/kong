package api

import (
	"encoding/json"
	"log"
	"net/http"
)

//Example of a scope that requires user login
func HandleUserGET(w http.ResponseWriter, r *http.Request) {
	claims := r.Context().Value("userclaims")

	if claims == nil {
		log.Println("Claims Empty")
		http.Error(w, "", http.StatusUnauthorized)
		return
	}

	bits, err := json.Marshal(claims)

	if err != nil {
		log.Println("Marshal Error", err)
		http.Error(w, "", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Write(bits)
}
