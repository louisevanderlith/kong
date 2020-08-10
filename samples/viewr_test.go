package samples

import (
	"github.com/louisevanderlith/kong"
	"github.com/louisevanderlith/kong/samples/handlers/viewr"
	"github.com/louisevanderlith/kong/samples/servers/secure"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestHandleIndexGET_LoginRequired(t *testing.T) {
	authS := httptest.NewServer(GetAuthRoutes())
	defer authS.Close()

	ts := httptest.NewTLSServer(GetSecureRoutes(secure.Security))
	defer ts.Close()

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rr := httptest.NewRecorder()
	handl := kong.ClientMiddleware(ts.Client(), "kong.viewr", "secret", ts.URL, authS.URL, viewr.HandleIndexGET, map[string]bool{"api.user.view":true})
	handl(rr, req)

	if rr.Code != http.StatusTemporaryRedirect {
		t.Fatal(rr.Code, rr.Body.String())
	}
}
