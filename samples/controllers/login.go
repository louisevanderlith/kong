package controllers

import (
	"encoding/json"
	"github.com/louisevanderlith/kong/prime"
	"github.com/louisevanderlith/kong/samples/server"
	"io"
	"log"
	"net/http"
)

func HandleLoginGET(w http.ResponseWriter, r *http.Request) {
	//tmpl := fmt.Sprintf("<html><body>%v</body></html>", claims)
	io.WriteString(w, "<html><body><h1>Please login</h1></body></html>")
}

func HandleLoginPOST(w http.ResponseWriter, r *http.Request) {
	obj := prime.LoginRequest{}
	decoder := json.NewDecoder(r.Body)

	err := decoder.Decode(&obj)

	if err != nil {
		log.Println(err)
		w.WriteHeader(http.StatusBadRequest)
		w.Write(nil)
		return
	}

	ut, err := server.Author.Authorize(obj.Client, obj.Username, obj.Password)

	if err != nil {
		log.Println(err)
		w.WriteHeader(http.StatusBadRequest)
		w.Write(nil)
		return
	}

	session, err := server.Author.Cookies.Get(r, "sess-store")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	tkn, err := ut.Encode(&server.Author.SignCert.PublicKey)

	if err != nil {
		log.Println(err)
		w.WriteHeader(http.StatusInternalServerError)
		w.Write(nil)
		return
	}

	session.Values["user.token"] = tkn

	err = session.Save(r, w)
	if err != nil {
		log.Println(err)
		w.WriteHeader(http.StatusInternalServerError)
		w.Write(nil)
		return
	}

	http.Redirect(w, r, "/consent", http.StatusFound)
}
