package secure

import (
	"encoding/json"
	"github.com/louisevanderlith/kong/prime"
	"github.com/louisevanderlith/kong/samples/servers/secure"
	"log"
	"net/http"
)

//ClientInsight
func HandleInfoPOST(w http.ResponseWriter, r *http.Request) {
	_, pass, ok := r.BasicAuth()

	if !ok {
		http.Error(w, "", http.StatusUnauthorized)
		return
	}

	dec := json.NewDecoder(r.Body)
	req := prime.QueryRequest{}
	err := dec.Decode(&req)

	if err != nil {
		log.Println(err)
		http.Error(w, "", http.StatusBadRequest)
		return
	}

	claims, err := secure.Security.ClientInsight(req.Token, pass)

	if err != nil {
		log.Println("Info Error", err)
		http.Error(w, "", http.StatusBadRequest)
		return
	}

	bits, err := json.Marshal(claims)

	if err != nil {
		log.Println("Marshal Error", err)
		http.Error(w, "", http.StatusInternalServerError)
		return
	}

	w.Write(bits)
}
