package controllers

import (
	"fmt"
	"github.com/go-session/session"
	"github.com/louisevanderlith/kong/samples/server"
	"github.com/louisevanderlith/kong/signing"
	"io"
	"log"
	"net/http"
	"strings"
)

func HandleConsentGET(w http.ResponseWriter, r *http.Request) {
	store, err := session.Start(nil, w, r)
	if err != nil {
		log.Println("no session store", err)
		w.WriteHeader(http.StatusInternalServerError)
		w.Write(nil)
		return
	}

	ut, ok := store.Get("user.token")

	if !ok {
		w.Header().Set("Location", "/login")
		w.WriteHeader(http.StatusFound)
		return
	}

	clms, err := signing.DecodeToken(ut.(string), server.Author.SignCert)

	if err != nil {
		log.Println(err)
		w.WriteHeader(http.StatusInternalServerError)
		w.Write(nil)
		return
	}

	_, username := clms.GetUserinfo()
	cname := clms.GetClient()
	_, clnt, err := server.Author.GetProfileClient(cname)

	concern := strings.Builder{}

	for _, v := range clnt.AllowedResources {
		rsrc, err := server.Author.Resources.GetResource(v)

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

	tmpl := fmt.Sprintf("<html><body><span>Hello %s</span><p>%s requires access to the following:</p> <ul>%s</ul></body></html>", username, cname, concern.String())
	io.WriteString(w, tmpl)
}

func HandleConsentPOST(w http.ResponseWriter, r *http.Request) {
//server.Author.Consent()
}
