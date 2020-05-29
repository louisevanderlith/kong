package secure

import (
	"encoding/json"
	"github.com/louisevanderlith/kong/samples/servers/secure"
	"log"
	"net/http"

	"github.com/louisevanderlith/kong/prime"
)

func HandleInspectPOST(w http.ResponseWriter, r *http.Request) {
	scp, pass, ok := r.BasicAuth()

	if !ok {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write(nil)
		return
	}

	dec := json.NewDecoder(r.Body)
	req := prime.InspectReq{}
	err := dec.Decode(&req)

	if err != nil {
		log.Println(err)
		w.WriteHeader(http.StatusBadRequest)
		w.Write(nil)
		return
	}

	claims, err := secure.Author.Inspect(req.AccessCode, scp, pass)

	if err != nil {
		log.Println(err)
		w.WriteHeader(http.StatusBadRequest)
		w.Write(nil)
		return
	}

	bits, err := json.Marshal(claims)

	if err != nil {
		log.Println(err)
		w.WriteHeader(http.StatusInternalServerError)
		w.Write(nil)
		return
	}

	w.Write(bits)
}