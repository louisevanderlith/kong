package entity

import (
	"encoding/json"
	"github.com/louisevanderlith/kong/prime"
	"github.com/louisevanderlith/kong/samples/servers/entity"
	"log"
	"net/http"
)

func HandleConsentPOST(w http.ResponseWriter, r *http.Request) {
	obj := prime.QueryRequest{}
	decoder := json.NewDecoder(r.Body)

	err := decoder.Decode(&obj)

	if err != nil {
		log.Println(err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	ut, err := entity.Manager.Consent(obj.Token, obj.Claims)

	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	enc, err := entity.Manager.Sign(ut, 5)

	if err != nil {
		log.Println(err)
		w.WriteHeader(http.StatusInternalServerError)
		w.Write(nil)
		return
	}

	bits, err := json.Marshal(enc)

	if err != nil {
		log.Println(err)
		w.WriteHeader(http.StatusInternalServerError)
		w.Write(nil)
		return
	}

	w.Write(bits)
}
