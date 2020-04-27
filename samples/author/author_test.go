package author_test

import (
	"bytes"
	"encoding/json"
	models2 "github.com/louisevanderlith/kong/models"
	"github.com/louisevanderlith/kong/samples/author/controllers"
	"github.com/louisevanderlith/kong/samples/author/models"
	"github.com/louisevanderlith/kong/tokens"
	"log"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestHandleTokenPOST(t *testing.T) {
	tknReq := models.TokenReq{
		UserToken: tokens.UserToken{},
		Scope:     "profile.info",
	}
	obj, err := json.Marshal(tknReq)

	if err != nil {
		t.Error(err)
		return
	}

	req := httptest.NewRequest(http.MethodPost, "/token", bytes.NewBuffer(obj))
	req.SetBasicAuth("kong.www", "secret")
	rr := httptest.NewRecorder()
	controllers.HandleTokenPOST(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatal(rr.Code, rr.Body.String())
		return
	}

	if len(rr.Body.String()) == 0 {
		t.Error("no body")
	}
}

func TestHandleInspectPOST(t *testing.T) {
	tknReq := models.TokenReq{
		UserToken: tokens.UserToken{},
		Scope:     "profile.info",
	}
	tknobj, err := json.Marshal(tknReq)

	if err != nil {
		t.Error(err)
		return
	}

	req := httptest.NewRequest(http.MethodPost, "/token", bytes.NewBuffer(tknobj))
	req.SetBasicAuth("kong.www", "secret")
	rr := httptest.NewRecorder()
	controllers.HandleTokenPOST(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatal(rr.Code, rr.Body.String())
		return
	}

	body := rr.Body.String()
	if len(body) == 0 {
		t.Error("no body")
	}
	log.Println(body)
	insReq := models2.InspectReq{AccessCode: body}
	obj, err := json.Marshal(insReq)

	if err != nil {
		t.Fatal(err)
		return
	}

	ireq := httptest.NewRequest(http.MethodPost, "/inspect", bytes.NewBuffer(obj))
	ireq.SetBasicAuth("api.view.profile", "secret")
	irr := httptest.NewRecorder()
	controllers.HandleInspectPOST(irr, ireq)

	if irr.Code != http.StatusOK {
		t.Fatal(irr.Code, irr.Body.String())
	}

	clms := make(map[string]string)
	dec := json.NewDecoder(irr.Body)
	err = dec.Decode(&clms)

	if err != nil {
		t.Fatal(err)
		return
	}

	if clms["profile.info.name"] != "kong" {
		t.Error("unexpected claim value", clms["profile.info.name"])
	}
}
