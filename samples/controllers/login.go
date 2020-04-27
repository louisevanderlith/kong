package controllers

import (
	"github.com/louisevanderlith/kong/samples/server"
	"io"
	"net/http"
)

func HandleLoginGET(w http.ResponseWriter, r *http.Request) {
	//tmpl := fmt.Sprintf("<html><body>%v</body></html>", claims)
	io.WriteString(w, "<html><body><h1>Please login</h1></body></html>")
}

func HandleLoginPOST(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()
	clnt := r.FormValue("client")
	usrname := r.FormValue("username")
	pass := r.FormValue("password")
	server.Author.Authorize(clnt, usrname, pass)
}