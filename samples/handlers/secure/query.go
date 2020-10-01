package secure

import (
	"encoding/json"
	"github.com/gorilla/mux"
	"github.com/louisevanderlith/kong/samples/servers/secure"
	"log"
	"net/http"
)

func HandleClientQueryGET(w http.ResponseWriter, r *http.Request) {
	client := mux.Vars(r)["client"]

	res, err := secure.Security.ClientResourceQuery(client)

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
