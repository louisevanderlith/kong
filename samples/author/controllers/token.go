package controllers

import (
	"kong"
	"net/http"
)

func HandleTokenPOST(w http.ResponseWriter, r *http.Request) http.Handler {
	authr := kong.Authority{
		Profiles: newFakePS(),
		Users:    newFakeUS(),
		Scopes:   newFakeSS(),
	}


}
