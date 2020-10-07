package entitymanager

import (
	"github.com/louisevanderlith/droxolite/drx"
	"github.com/louisevanderlith/kong/prime"
	"log"
	"net/http"
)

//LoginPOSTHandler Attempts to login against the provided credentials
func LoginPOSTHandler(w http.ResponseWriter, r *http.Request) {
	obj := prime.LoginRequest{}
	err := drx.JSONBody(r, &obj)

	if err != nil {
		log.Println("Bind Error", err)
		http.Error(w, "", http.StatusBadRequest)
		return
	}

	tkn, err := _manager.Login(obj.Client, obj.Username, obj.Password)

	if err != nil {
		log.Println("Login Error", err)
		http.Error(w, "", http.StatusBadRequest)
		return
	}

	stkn, err := _manager.Sign(tkn, 5)

	if err != nil {
		log.Println("Sign Error", err)
		http.Error(w, "", http.StatusBadRequest)
		return
	}

	w.Write([]byte(stkn))
}
