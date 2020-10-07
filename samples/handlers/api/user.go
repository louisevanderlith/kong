package api

import (
	"github.com/louisevanderlith/droxolite/mix"
	"github.com/louisevanderlith/kong/middle"
	"log"
	"net/http"
)

//Example of a scope that requires user login
func HandleUserGET(w http.ResponseWriter, r *http.Request) {
	claims := middle.GetUserIdentity(r)

	if claims == nil {
		http.Error(w, "", http.StatusUnauthorized)
		return
	}

	err := mix.Write(w, mix.JSON(claims))

	if err != nil {
		log.Println("Serve Error", err)
	}
}
