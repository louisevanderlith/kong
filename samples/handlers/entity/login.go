package entity

import (
	"encoding/json"
	"github.com/louisevanderlith/kong/prime"
	"github.com/louisevanderlith/kong/samples/servers/entity"
	"github.com/louisevanderlith/kong/samples/servers/secure"
	"log"
	"net/http"
)

func HandleLoginPOST(w http.ResponseWriter, r *http.Request) {
	obj := prime.LoginRequest{}
	decoder := json.NewDecoder(r.Body)

	err := decoder.Decode(&obj)

	if err != nil {
		log.Println("Bind Error", err)
		http.Error(w, "", http.StatusBadRequest)
		return
	}

	tkn, err := entity.Manager.Login(obj.Client, obj.Username, obj.Password)

	if err != nil {
		log.Println("Login Error", err)
		http.Error(w, "", http.StatusBadRequest)
		return
	}

	stkn, err := secure.Security.Sign(tkn, 5)

	if err != nil {
		log.Println("Sign Error", err)
		http.Error(w, "", http.StatusBadRequest)
		return
	}

	w.Write([]byte(stkn))
}
