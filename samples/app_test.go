package samples

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/louisevanderlith/kong/samples/controllers"
	"github.com/louisevanderlith/kong/samples/models"
	"github.com/louisevanderlith/kong/tokens"
)

func TestHandleIndexGET_MusTfail(t *testing.T) {
	wwwtokn, err := getWWWToken()

	if err != nil {
		t.Fatal(err)
		return
	}

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer "+wwwtokn)
	// add Bearer header
	rr := httptest.NewRecorder()
	controllers.HandelIndexGET(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatal(rr.Code, rr.Body.String())
	}

	log.Println(rr.Body.String())
}

func getWWWToken() (string, error) {
	tknReq := models.TokenReq{
		UserToken: tokens.UserToken{},
		Scope:     "api.view.profile",
	}
	obj, err := json.Marshal(tknReq)

	if err != nil {
		return "", err
	}

	req := httptest.NewRequest(http.MethodPost, "/token", bytes.NewBuffer(obj))
	req.SetBasicAuth("kong.viewr", "secret")
	rr := httptest.NewRecorder()
	controllers.HandleTokenPOST(rr, req)

	if rr.Code != http.StatusOK {
		msg := fmt.Sprintf("Code: %v, Error: %s", rr.Code, rr.Body.String())
		return "", errors.New(msg)
	}

	if len(rr.Body.String()) == 0 {
		return "", errors.New("no body")
	}

	return rr.Body.String(), nil
}
