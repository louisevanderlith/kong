package entitymanager

import (
	"github.com/louisevanderlith/droxolite/mix"
	"github.com/louisevanderlith/kong/middle"
	"log"
	"net/http"
)

func InsightPOSTHandler(w http.ResponseWriter, r *http.Request) {
	idn := middle.GetIdentity(r)

	if !idn.HasUser() {
		log.Println("No User for Insight")
		http.Error(w, "", http.StatusBadRequest)
		return
	}

	ut, err := _manager.Insight(idn.GetUserToken())

	if err != nil {
		log.Println("Insight Error", err)
		http.Error(w, "", http.StatusInternalServerError)
		return
	}

	err = mix.Write(w, mix.JSON(ut))

	if err != nil {
		log.Println("Serve Error", err)
	}
}
