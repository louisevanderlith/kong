package samples

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

/*
	Client Application flow that requires user login to call a resource.
	This is the fullest flow, and the reason kong was built.
	1. Browser hits Client Middleware.
	2. ObtainToken (Will fail, as user or consent is not provided)
	3. Consent (To obtain user's consent on Scopes and their claims)
	4. Login (Displays Login)
	5. AuthenticateUser (Login POST)
	6. Consent (Displays the application's required scopes to user)
	7. AuthorizeConsent (Consent POST)
	8. Send UserToken to Client (Callback)
	9. Goto 1.
*/
/*
func TestFlow_User(t *testing.T) {
	appId := "kong.viewr"
	ts := httptest.NewServer(GetSecureRoutes())
	defer ts.Close()



	// Try to obtain token, should fail since we're requesting a user claim
	_, err := secure.Security.RequestToken(appId, "secret", "", map[string]bool{"api.user.view": true})

	if err == nil {
		t.Error("unexpected success, user should be required")
		return
	}

	// Obtain Partial login Token
	partClms, err := entity.Manager.Login(appId, "user@fake.com", "user1pass")

	if err != nil {
		t.Error(err)
		return
	}

	partial, err := entity.Manager.Sign(partClms, 5)

	if err != nil {
		t.Error(err)
		return
	}

	// Apply Consent to Partial token
	consent := map[string]bool{
		tokens.UserName: true,
		tokens.UserKey:  true,
	}

	usrClms, err := entity.Manager.Consent(partial, consent)

	if err != nil {
		t.Error(err)
		return
	}

	ut, err := entity.Manager.Sign(usrClms, 5)

	if err != nil {
		t.Error(err)
		return
	}

	tkn, err := secure.Security.RequestToken(appId, "secret", ut, map[string]bool{"api.user.view": true})

	if err != nil {
		t.Error(err)
		return
	}

	if !tkn.HasUser() {
		t.Error("user expected")
		return
	}

	usrIdn, err := entity.Manager.FetchNeeds(tkn.GetUserToken())

	if err != nil {
		t.Error("Fetch Needs Error", err)
		return
	}
	log.Println("TKN", usrIdn)
	if !usrIdn.HasClaim(tokens.UserName) {
		t.Error("token doesn't have 'UserName' claim")
		return
	}

	act := usrIdn.GetClaim(tokens.UserName)
	exp := "User 1"
	if act != exp {
		t.Errorf("incorrect claim; want %s, got %s", exp, act)
	}
}*/

func TestHandleIndexGET_LoginRequired(t *testing.T) {
	ts := httptest.NewTLSServer(GetSecureRoutes())
	defer ts.Close()

	es := httptest.NewTLSServer(GetEntityRoutes(ts.Client(), ts.URL))
	defer es.Close()

	authS := httptest.NewServer(GetAuthRoutes(es.Client(), ts.URL, es.URL, "kong.auth", "secret"))
	defer authS.Close()

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rr := httptest.NewRecorder()

	app := GetViewrRoutes("kong.viewr", "secret", authS.Client(), ts.URL, es.URL, authS.URL)

	app.ServeHTTP(rr, req)

	if rr.Code != http.StatusTemporaryRedirect {
		t.Fatal(rr.Code, rr.Body.String())
	}
}
