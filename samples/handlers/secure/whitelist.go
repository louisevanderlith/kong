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
		w.WriteHeader(http.StatusUnauthorized)
		w.Write(nil)
		return
	}

	rsrc, err := secure.Author.GetStore().GetResource(api)

	if !rsrc.VerifySecret(pass) {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write(nil)
		return
	}

	lst := secure.Author.GetStore().GetWhitelist()

	bits, err := json.Marshal(lst)

	if err != nil {
		log.Println(err)
		w.WriteHeader(http.StatusInternalServerError)
		w.Write(nil)
		return
	}

	w.Write(bits)
}
