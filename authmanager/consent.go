package authmanager

import (
	"fmt"
	"github.com/louisevanderlith/droxolite/drx"
	"github.com/louisevanderlith/droxolite/mix"
	"github.com/louisevanderlith/kong/prime"
	"log"
	"net/http"
	"net/url"
)

func InitialConsentHandler(w http.ResponseWriter, r *http.Request) {
	cbUrl := drx.FindQueryParam(r, "callback")

	if len(cbUrl) == 0 {
		http.Error(w, "no callback query", http.StatusBadRequest)
		return
	}

	log.Println("REF:", r.Referer())
	log.Println("CB:", cbUrl)

	state := drx.FindQueryParam(r, "state")

	if len(state) == 0 {
		log.Println("no 'state' query")
		http.Error(w, "", http.StatusBadRequest)
		return
	}

	client := drx.FindQueryParam(r, "client")

	if len(client) == 0 {
		log.Println("no 'client' query")
		http.Error(w, "", http.StatusBadRequest)
		return
	}

	sessn, err := _sessionStore.Get(r, "partial")

	if err != nil {
		log.Println("New Session Error", err)
		http.Error(w, "", http.StatusInternalServerError)
		return
	}

	sessn.Values[state] = r.Referer()

	err = sessn.Save(r, w)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	loginUrl := fmt.Sprintf("/login?state=%s&client=%s", state, client)
	http.Redirect(w, r, loginUrl, http.StatusFound)
}

func UserConsentHandler(pge mix.MixerFactory) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		partial := drx.FindQueryParam(r, "partial")

		if len(partial) == 0 {
			log.Println("no 'partial' query")
			http.Error(w, "", http.StatusBadRequest)
			return
		}

		state := drx.FindQueryParam(r, "state")

		if len(state) == 0 {
			log.Println("no 'state' query")
			http.Error(w, "", http.StatusBadRequest)
			return
		}

		client := drx.FindQueryParam(r, "client")

		if len(client) == 0 {
			log.Println("no 'client' query")
			http.Error(w, "", http.StatusBadRequest)
			return
		}

		cc, err := _authority.ClientQuery(client)

		if err != nil {
			log.Println("Client Query Error", err)
			http.Error(w, "", http.StatusInternalServerError)
			return
		}

		sessn, err := _sessionStore.Get(r, "partial")

		if err != nil {
			log.Println("Invalid Session Error", err)
			http.Error(w, "", http.StatusInternalServerError)
			return
		}

		cbUrl := sessn.Values[state]

		if len(cbUrl.(string)) == 0 {
			http.Error(w, "no callback found", http.StatusBadRequest)
			return
		}

		result := struct {
			ID       string
			Username string
			Callback string
			Concern  map[string][]string
		}{
			ID:       cc.Client,
			Username: "Userx",
			Callback: cbUrl.(string),
			Concern:  cc.Needs,
		}

		err = mix.Write(w, pge.Create(r, result))

		if err != nil {
			log.Println("Serve Error", err)
		}
	}
}

func ConsentPOSTHandler(w http.ResponseWriter, r *http.Request) {
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

	session, err := _sessionStore.Get(r, "partial")

	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	ut := session.Values["user.token"]

	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	obj := prime.QueryRequest{
		Token:  ut.(string),
		Claims: nil,
	}

	tkn, err := _authority.GiveConsent(obj)

	if err != nil {
		log.Println("Give Consent Error", err)
		//Show consent again
		return
	}

	raw, err := url.Parse(cbUrls[0])

	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	cb := fmt.Sprintf("%s://%s/callback?ut=%s&redirect=%s", raw.Scheme, raw.Host, tkn, cbUrls[0])
	http.Redirect(w, r, cb, http.StatusFound)
}
