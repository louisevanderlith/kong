package entity

import (
	"encoding/json"
	"github.com/louisevanderlith/kong/prime"
	"github.com/louisevanderlith/kong/samples/servers/entity"
	"log"
	"net/http"
)

func HandleInsightPost(w http.ResponseWriter, r *http.Request) {
	obj := prime.QueryRequest{}
	decoder := json.NewDecoder(r.Body)

	err := decoder.Decode(&obj)

	if err != nil {
		log.Println(err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	ut, err := entity.Manager.Insight(obj)

	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	bits, err := json.Marshal(ut)

	if err != nil {
		log.Println(err)
		http.Error(w, "", http.StatusInternalServerError)
		return
	}

	w.Write(bits)
}
