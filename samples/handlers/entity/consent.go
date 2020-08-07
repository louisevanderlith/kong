package entity

import (
	"encoding/json"
	"github.com/louisevanderlith/kong/prime"
	"github.com/louisevanderlith/kong/samples/servers/entity"
	"github.com/louisevanderlith/kong/samples/servers/secure"
	"log"
	"net/http"
)

func HandleClientQueryPOST(w http.ResponseWriter, r *http.Request) {
	obj := prime.QueryRequest{}
	decoder := json.NewDecoder(r.Body)

	err := decoder.Decode(&obj)

	if err != nil {
		log.Println("Bind Error", err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	res, err := secure.Security.QueryClient(obj.Partial)

	if err != nil {
		log.Println("Query Client Error", err)
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}
	bits, err := json.Marshal(res)

	if err != nil {
		log.Println("Marshal Error", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Write(bits)
}

func HandleConsentPOST(w http.ResponseWriter, r *http.Request) {
	obj := prime.ConsentRequest{}
	decoder := json.NewDecoder(r.Body)

	err := decoder.Decode(&obj)

	if err != nil {
		log.Println(err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	ut, err := entity.Manager.Consent(obj.UserToken, obj.Claims)

	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	enc, err := secure.Security.Sign(ut, 5)

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
