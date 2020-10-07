package securitymanager

import (
	"github.com/louisevanderlith/droxolite/drx"
	"github.com/louisevanderlith/droxolite/mix"
	"github.com/louisevanderlith/kong/prime"
	"log"
	"net/http"
)

//ResourceInfoHandler returns Resource Insight
func ResourceInfoHandler(w http.ResponseWriter, r *http.Request) {
	scp, pass, ok := r.BasicAuth()

	if !ok {
		http.Error(w, "", http.StatusUnauthorized)
		return
	}

	req := prime.QueryRequest{}
	err := drx.JSONBody(r, &req)

	if err != nil {
		log.Println("Bind Error", err)
		http.Error(w, "", http.StatusBadRequest)
		return
	}

	claims, err := _security.ResourceInsight(req.Token, scp, pass)

	if err != nil {
		log.Println("Inspect Error", err)
		http.Error(w, "", http.StatusBadRequest)
		return
	}

	err = mix.Write(w, mix.JSON(claims))

	if err != nil {
		log.Println("Serve Error", err)
		return
	}
}

//ClientInfoHandler returns Client Insight
func ClientInfoHandler(w http.ResponseWriter, r *http.Request) {
	_, pass, ok := r.BasicAuth()

	if !ok {
		http.Error(w, "", http.StatusUnauthorized)
		return
	}

	req := prime.QueryRequest{}
	err := drx.JSONBody(r, &req)

	if err != nil {
		log.Println("Bind Error", err)
		http.Error(w, "", http.StatusBadRequest)
		return
	}

	claims, err := _security.ClientInsight(req.Token, pass)

	if err != nil {
		log.Println("Info Error", err)
		http.Error(w, "", http.StatusBadRequest)
		return
	}

	err = mix.Write(w, mix.JSON(claims))

	if err != nil {
		log.Println("Serve Error", err)
	}
}
