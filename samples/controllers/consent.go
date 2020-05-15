package controllers

import (
	"encoding/json"
	"fmt"
	"github.com/louisevanderlith/kong/prime"
	"github.com/louisevanderlith/kong/samples/server"
	"github.com/louisevanderlith/kong/tokens"
	"io"
	"log"
	"net/http"
	"strings"
)

func HandleConsentGET(w http.ResponseWriter, r *http.Request) {
	brrl, err := server.Author.Barrel(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if !brrl.HasUser() {
		w.Header().Set("Location", "/login")
		w.WriteHeader(http.StatusFound)
		return
	}

	_, username := brrl.GetUserinfo()
	_, clnt, err := server.Author.GetProfileClient(brrl)

	if err != nil {
		log.Println(err)
		w.WriteHeader(http.StatusInternalServerError)
		w.Write(nil)
		return
	}

	concern := strings.Builder{}

	for _, v := range clnt.AllowedResources {
		rsrc, err := server.Author.Store.GetResource(v)

		if err != nil {
			log.Println(err)
			w.WriteHeader(http.StatusInternalServerError)
			w.Write(nil)
			return
		}

		parnt := fmt.Sprintf("<li>%s<ul>", rsrc.DisplayName)
		concern.WriteString(parnt)

		for _, n := range rsrc.Needs {
			li := fmt.Sprintf("<li><input type=\"checkbox\" checked value=\"%s\"/></li>", n)
			concern.WriteString(li)
		}

		concern.WriteString("</ul></li>")
	}

	tmpl := fmt.Sprintf("<html><body><span>Hello %s</span><p>%s requires access to the following:</p> <ul>%s</ul></body></html>", username, brrl.GetId(), concern.String())
	io.WriteString(w, tmpl)
}

func HandleConsentPOST(w http.ResponseWriter, r *http.Request) {
	obj := prime.ConsentRequest{}
	decoder := json.NewDecoder(r.Body)

	err := decoder.Decode(&obj)

	if err != nil {
		log.Println(err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	session, err := server.Author.Cookies.Get(r, "sess-store")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	clms, err := server.Author.Consent(session.Values["user.id"].(tokens.Claims), obj.Claims...)

	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	prof, clnt, err := server.Author.GetProfileClient(clms)

	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	http.Redirect(w, r, fmt.Sprintf("https://%s.%s/callback", strings.ToLower(clnt.Name), prof.Domain), http.StatusFound)
}
