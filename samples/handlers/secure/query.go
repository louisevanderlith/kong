package secure

import (
	"encoding/json"
	"github.com/louisevanderlith/kong/prime"
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

	res, err := secure.Security.QueryClient(obj.Token)

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
