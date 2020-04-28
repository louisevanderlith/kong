package controllers

import (
	"fmt"
	"io"
	"net/http"
)

func HandelIndexGET(w http.ResponseWriter, r *http.Request) {
	claims := r.Context().Value("claims")

	if claims == nil {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write(nil)
		return
	}

	tmpl := fmt.Sprintf("<html><body>%v</body></html>", claims)
	io.WriteString(w, tmpl)
}
