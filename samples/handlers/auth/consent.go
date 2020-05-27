package auth

import (
	"fmt"
	"github.com/louisevanderlith/kong/prime"
	"github.com/louisevanderlith/kong/samples/servers/auth"
	"io"
	"log"
	"net/http"
	"strings"
)

func HandleConsentGET(w http.ResponseWriter, r *http.Request) {
	sessn, err := auth.SessionStore.Get(r, "partial")

	if err != nil {
		log.Println(err)
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}

	ut, ok := sessn.Values["user.token"]

	if !ok {
		log.Println(err)
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}

	req := prime.QueryRequest{Partial: ut.(string)}

	user, concern, err := auth.Security.ClientQuery(req)

	if err != nil {
		log.Println(err)
		w.WriteHeader(http.StatusInternalServerError)
		w.Write(nil)
		return
	}

	items := strings.Builder{}

	for k, v := range concern {

		if err != nil {
			log.Println(err)
			http.Error(w, "", http.StatusInternalServerError)
			return
		}

		parnt := fmt.Sprintf("<li>%s<ul>", k)
		items.WriteString(parnt)

		for _, n := range v {
			li := fmt.Sprintf("<li><input type=\"checkbox\" checked value=\"%v\"/></li>", n)
			items.WriteString(li)
		}

		items.WriteString("</ul></li>")
	}

	clnts := r.URL.Query()["client"]

	if len(clnts) == 0 {
		http.Error(w, "no client query", http.StatusBadRequest)
		return
	}

	cbUrls := r.URL.Query()["callback"]

	if len(cbUrls) == 0 {
		http.Error(w, "no callback query", http.StatusBadRequest)
		return
	}

	tmpl := fmt.Sprintf("<html><body><span>Hello %s</span><p>%s requires access to the following:</p> <ul>%s</ul></body></html>", user, clnts[0], items.String())
	io.WriteString(w, tmpl)
}

func HandleConsentPOST(w http.ResponseWriter, r *http.Request) {
	clnts := r.URL.Query()["client"]

	if len(clnts) == 0 {
		http.Error(w, "no client query", http.StatusBadRequest)
		return
	}

	cbUrls := r.URL.Query()["callback"]

	if len(cbUrls) == 0 {
		http.Error(w, "no callback query", http.StatusBadRequest)
		return
	}

	session, err := auth.SessionStore.Get(r, "partial")

	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	ut := session.Values["user.token"]

	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	obj := prime.ConsentRequest{
		User:   ut.(string),
		Claims: r.Form["consent"],
	}

	tkn, err := auth.Security.GiveConsent(obj)

	if err != nil {
		log.Println(err)
		//Show consent again
		return
	}

	http.Redirect(w, r, fmt.Sprintf("%s?ut=%s", cbUrls[0], tkn), http.StatusFound)
}
