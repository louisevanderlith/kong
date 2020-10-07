package securitymanager

import (
	"github.com/louisevanderlith/droxolite/mix"
	"log"
	"net/http"
)

func WhitelistGET(w http.ResponseWriter, r *http.Request) {
	scp, pass, ok := r.BasicAuth()

	if !ok {
		http.Error(w, "", http.StatusUnauthorized)
		return
	}

	res, err := _security.Whitelist(scp, pass)

	if err != nil {
		log.Println("Whitelist Error", err)
		http.Error(w, "", http.StatusUnauthorized)
		return
	}

	err = mix.Write(w, mix.JSON(res))

	if err != nil {
		log.Println("Serve Error", err)
	}
}
