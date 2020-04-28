package samples

import (
	"bytes"
	"encoding/json"
	"io/ioutil"
	"log"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/louisevanderlith/kong/prime"
	"github.com/louisevanderlith/kong/samples/controllers"
	"github.com/louisevanderlith/kong/samples/models"
	"github.com/louisevanderlith/kong/tokens"
)

func TestHandleTokenPOST(t *testing.T) {
	tknReq := models.TokenReq{
		UserToken: tokens.UserToken{},
		Scope:     "api.view.profile",
	}
	obj, err := json.Marshal(tknReq)

	if err != nil {
		t.Error(err)
		return
	}

	req := httptest.NewRequest(http.MethodPost, "/token", bytes.NewBuffer(obj))
	req.SetBasicAuth("kong.viewr", "secret")
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
		Scope:     "profile",
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
	insReq := prime.InspectReq{AccessCode: body}
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

	if clms["profile.name"] != "kong" {
		t.Error("unexpected claim value", clms["profile.name"])
	}
}

func TestHandleInfoPOST(t *testing.T) {
	tknReq := models.TokenReq{
		UserToken: tokens.UserToken{},
		Scope:     "profile",
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
	insReq := prime.InspectReq{AccessCode: body}
	obj, err := json.Marshal(insReq)

	if err != nil {
		t.Fatal(err)
		return
	}

	ireq := httptest.NewRequest(http.MethodPost, "/info", bytes.NewBuffer(obj))
	ireq.SetBasicAuth("kong.www", "secret")
	irr := httptest.NewRecorder()
	controllers.HandleInfoPOST(irr, ireq)

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

	if clms["kong.profile"] != "kong" {
		t.Error("unexpected claim value", clms["kong.profile"])
	}
}

func TestHandleConsentGET_NotAuthenticated(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/consent", nil)
	rr := httptest.NewRecorder()
	controllers.HandleConsentGET(rr, req)

	resp := rr.Result()
	url, err := resp.Location()

	if err != nil {
		t.Fatal(err)
		return
	}

	if url.Path != "/login" {
		t.Errorf("invalid url %s", url)
		return
	}

	if rr.Code != http.StatusFound {
		t.Fatal(rr.Code, rr.Body.String())
		return
	}

	body, err := ioutil.ReadAll(resp.Body)

	if err != nil {
		t.Fatal(err)
		return
	}

	log.Println(body)
	if len(body) == 0 {
		t.Error("no body")
	}
}
