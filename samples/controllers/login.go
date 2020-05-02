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
	/*session, err := server.Author.Cookies.Get(r, "sess-store")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}*/

	//tmpl := fmt.Sprintf("<html><body>%v</body></html>", claims)
	io.WriteString(w, "<html><body><h1>Please login</h1><form></form></body></html>")
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

	id, err := server.Author.AuthenticateUser(obj.Username, obj.Password)

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

	session.Values["user.id"] = id

	err = session.Save(r, w)
	if err != nil {
		log.Println(err)
		w.WriteHeader(http.StatusInternalServerError)
		w.Write(nil)
		return
	}

	http.Redirect(w, r, "/consent?client=", http.StatusFound)
}
