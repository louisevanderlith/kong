package secure

import (
	"encoding/json"
	"github.com/louisevanderlith/kong/samples/servers/secure"
	"log"
	"net/http"
)

func WhitelistGET(w http.ResponseWriter, r *http.Request) {
	api, pass, ok := r.BasicAuth()

	if !ok {
		http.Error(w, "", http.StatusUnauthorized)
		return
	}

	lst, err := secure.Security.Whitelist(api, pass)

	if err != nil {
		log.Println("Whitelist Error", err)
		http.Error(w, "", http.StatusInternalServerError)
		return
	}

	bits, err := json.Marshal(lst)

	if err != nil {
		log.Println("Marshal Error", err)
		http.Error(w, "", http.StatusInternalServerError)
		return
	}

	w.Write(bits)
}
