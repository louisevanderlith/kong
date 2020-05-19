package tests

import (
	"github.com/louisevanderlith/kong"
	"github.com/louisevanderlith/kong/samples/controllers"
	"log"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestClient_Callback_MustsetCookie_FullUserToken(t *testing.T){

	req := httptest.NewRequest(http.MethodGet, "/callback?user=", nil)

	rr := httptest.NewRecorder()

	handle := kong.ResourceMiddleware("api.profile.view", "secret", "https://localhost:000", controllers.HandleProfileGET)
	handle(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatal(rr.Code, rr.Body.String())
	}

	log.Println(rr.Body.String())
}

