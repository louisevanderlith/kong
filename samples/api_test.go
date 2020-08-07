package samples

import (
	"github.com/louisevanderlith/kong/samples/handlers/api"
	"github.com/louisevanderlith/kong/samples/servers/secure"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/louisevanderlith/kong"
)

func TestResource_Middleware_SetContext(t *testing.T) {
	ts := httptest.NewTLSServer(GetSecureRoutes(secure.Security))
	defer ts.Close()

	token, err := ObtainToken(ts, "kong.viewr", "secret", "api.profile.view")

	if err != nil {
		t.Fatal("Obtain Token Error", err)
		return
	}

	req := httptest.NewRequest(http.MethodGet, "/profile", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()

	handle := kong.ResourceMiddleware(ts.Client(), "api.profile.view", "secret", ts.URL, api.HandleProfileGET)
	handle(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatal(rr.Code, rr.Body.String())
	}
}
