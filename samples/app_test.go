package samples

import (
	"github.com/louisevanderlith/kong"
	"log"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/louisevanderlith/kong/samples/controllers"
)

func TestHandleIndexGET_MustLandOnLogin(t *testing.T) {
	ts := httptest.NewTLSServer(GetAuthRoutes())
	defer ts.Close()

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rr := httptest.NewRecorder()
	handl := kong.ClientMiddleware(ts.Client(), "kong.viewr", "secret", ts.URL, controllers.HandleIndexGET, "api.user.view")
	handl(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatal(rr.Code, rr.Body.String())
	}

	log.Println(rr.Body.String())
}
