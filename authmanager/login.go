package authmanager

import (
	"fmt"
	"github.com/louisevanderlith/droxolite/drx"
	"github.com/louisevanderlith/droxolite/mix"
	"github.com/louisevanderlith/kong/prime"
	"html/template"
	"log"
	"net/http"
)

func LoginGETHandler(tmpl *template.Template) http.HandlerFunc {
	pge := mix.PreparePage("Login", tmpl, "./views/login.html")
	//pge.AddMenu(FullMenu())
	return func(w http.ResponseWriter, r *http.Request) {
		client := drx.FindQueryParam(r, "client")

		if len(client) == 0 {
			log.Println("no 'client' query")
			http.Error(w, "", http.StatusBadRequest)
			return
		}

		state := drx.FindQueryParam(r, "state")

		if len(client) == 0 {
			log.Println("no 'state' query")
			http.Error(w, "", http.StatusBadRequest)
			return
		}

		obj := struct {
			State  string
			Client string
		}{state, client}

		err := mix.Write(w, pge.Create(r, obj))

		if err != nil {
			log.Println("Serve Error", err)
		}
	}
}

//LoginPOSTHandler is the server-side implementation of a Login POST
func HandleLoginPOST(w http.ResponseWriter, r *http.Request) {
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

	obj := prime.LoginRequest{
		Client:   clnts[0],
		Username: r.FormValue("username"),
		Password: r.FormValue("password"),
	}

	part, err := _authority.AuthenticateUser(obj)

	if err != nil {
		log.Println(err)
		//Show login again
		return
	}

	session, err := _sessionStore.Get(r, "partial")

	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	session.Values["user.token"] = part

	err = session.Save(r, w)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	http.Redirect(w, r, fmt.Sprintf("/consent?client=%s&callback=%s", clnts[0], cbUrls[0]), http.StatusFound)
}
