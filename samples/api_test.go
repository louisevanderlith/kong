package samples

import (
	"encoding/json"
	"github.com/louisevanderlith/kong/middle"
	"github.com/louisevanderlith/kong/samples/handlers/api"
	"github.com/louisevanderlith/kong/stores"
	"github.com/louisevanderlith/kong/tokens"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestResource_Middleware_SetContext(t *testing.T) {
	ts := httptest.NewTLSServer(GetSecureRoutes())
	defer ts.Close()

	token, err := ObtainToken(ts, []byte{}, "kong.viewr", "secret", map[string]bool{"api.profile.view": true})

	if err != nil {
		t.Fatal("Obtain Token Error", err)
		return
	}

	req := httptest.NewRequest(http.MethodGet, "/profile", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()

	svc := stores.NewAPIService(ts.Client(), ts.URL, "")
	mw := middle.NewResourceInspector(svc)
	handle := mw.Lock("api.profile.view", "secret", api.HandleProfileGET)
	handle(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatal(rr.Code, rr.Body.String())
	}
}

func TestResource_Middleware_SetContext_ForUsers(t *testing.T) {
	ts := httptest.NewTLSServer(GetSecureRoutes())
	defer ts.Close()

	tm := httptest.NewTLSServer(GetEntityRoutes(ts.Client(), ts.URL))
	defer tm.Close()

	token4user, err := ObtainUserLogin(tm, ts, "kong.viewr", "user@fake.com", "user1pass")

	if err != nil {
		t.Fatal("Obtain User Token Error", err)
		return
	}

	token, err := ObtainToken(ts, []byte(token4user), "kong.viewr", "secret", map[string]bool{"api.user.view": true})

	if err != nil {
		t.Fatal("Obtain Token Error", err)
		return
	}

	if len(token) == 0 {
		t.Error("token length 0")
		return
	}

	req := httptest.NewRequest(http.MethodGet, "/user", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()

	handle := GetApiRoutes(ts.Client(), ts.URL, tm.URL)
	handle.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatal(rr.Code, rr.Body.String())
	}

	result := tokens.EmptyClaims()
	dec := json.NewDecoder(rr.Body)
	err = dec.Decode(&result)

	if err != nil {
		t.Error("Bind Error", err)
		return
	}

	usrname := result.GetClaimString(tokens.UserName)
	if usrname != "User 1" {
		t.Error("unexpected value", usrname)
	}
}
