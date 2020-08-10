package secure

import (
	"encoding/json"
	"github.com/louisevanderlith/kong/samples/servers/secure"
	"log"
	"net/http"

	"github.com/louisevanderlith/kong/prime"
)

//Resource Insight
func HandleInspectPOST(w http.ResponseWriter, r *http.Request) {
	scp, pass, ok := r.BasicAuth()

	if !ok {
		http.Error(w, "", http.StatusUnauthorized)
		return
	}

	dec := json.NewDecoder(r.Body)
	req := prime.QueryRequest{}
	err := dec.Decode(&req)

	if err != nil {
		log.Println("Bind Error", err)
		http.Error(w, "", http.StatusBadRequest)
		return
	}

	claims, err := secure.Security.ResourceInsight(req.Token, scp, pass)

	if err != nil {
		log.Println("Inspect Error", err)
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
