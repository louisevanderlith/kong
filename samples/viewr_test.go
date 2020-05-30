package samples

import (
	"github.com/louisevanderlith/kong"
	"github.com/louisevanderlith/kong/samples/handlers/viewr"
	"github.com/louisevanderlith/kong/samples/servers/secure"
	"log"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestHandleIndexGET_LoginRequired(t *testing.T) {
	authS := httptest.NewServer(GetAuthRoutes())
	ts := httptest.NewTLSServer(GetSecureRoutes(secure.Author))
	defer ts.Close()

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rr := httptest.NewRecorder()
	handl := kong.ClientMiddleware(ts.Client(), "kong.viewr", "secret", ts.URL, authS.URL, viewr.HandleIndexGET, "api.user.view")
	handl(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatal(rr.Code, rr.Body.String())
	}

	log.Println(rr.Body.String())
}
