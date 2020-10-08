package securitymanager

import (
	"github.com/louisevanderlith/droxolite/drx"
	"github.com/louisevanderlith/droxolite/mix"
	"github.com/louisevanderlith/kong/prime"
	"log"
	"net/http"
)

func TokenPOSTHandler(w http.ResponseWriter, r *http.Request) {
	clnt, pass, ok := r.BasicAuth()

	if !ok {
		http.Error(w, "", http.StatusUnauthorized)
		return
	}

	req := prime.TokenRequest{}
	err := drx.JSONBody(r, &req)

	if err != nil {
		log.Println("Bind Error", err)
		http.Error(w, "", http.StatusBadRequest)
		return
	}

	clms, err := _security.RequestToken(clnt, pass, req.UserToken, req.Scopes)

	if err != nil {
		log.Println("Request Token Error", err)
		http.Error(w, "", http.StatusUnprocessableEntity)
		return
	}

	tkn, err := _security.Sign(clms, 5)

	if err != nil {
		log.Println("Sign Error", err)
		http.Error(w, "", http.StatusInternalServerError)
		return
	}

	exp, _ := clms.ExpiresAt()

	err = mix.Write(w, mix.JSON(prime.TokenResponse{
		Token:   tkn,
		Expires: exp,
	}))

	if err != nil {
		log.Println("Serve Error", err)
	}
}
