package controllers

import (
	"fmt"
	"github.com/louisevanderlith/kong/samples/server"
	"github.com/louisevanderlith/kong/signing"
	"io"
	"log"
	"net/http"
	"strings"
)

func HandleConsentGET(w http.ResponseWriter, r *http.Request) {
	session, err := server.Author.Cookies.Get(r, "sess-store")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	ut, ok := session.Values["user.token"]

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
	_, clnt, err := server.Author.GetProfileClient(clms.GetId())

	if err != nil {
		log.Println(err)
		w.WriteHeader(http.StatusInternalServerError)
		w.Write(nil)
		return
	}

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

	tmpl := fmt.Sprintf("<html><body><span>Hello %s</span><p>%s requires access to the following:</p> <ul>%s</ul></body></html>", username, clms.GetId(), concern.String())
	io.WriteString(w, tmpl)
}

func HandleConsentPOST(w http.ResponseWriter, r *http.Request) {
	//server.Author.Consent()
}
