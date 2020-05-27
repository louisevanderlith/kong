package samples

import (
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/louisevanderlith/kong/prime"
	"github.com/louisevanderlith/kong/samples/server"
	"log"
	http "net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"testing"
)

// Auth is the UI for Authentication

func ObtainUserLogin(srvr *httptest.Server, logintoken, clientId, username, password string) (string, error) {
	insReq := prime.LoginRequest{
		Client:   clientId,
		Username: username,
		Password: password,
	}
	obj, err := json.Marshal(insReq)

	if err != nil {
		return "", err
	}

	req, err := http.NewRequest(http.MethodPost, srvr.URL+"/login", bytes.NewBuffer(obj))
	req.Header.Set("Authorization", "Bearer "+logintoken)

	if err != nil {
		return "", err
	}

	jar, err := cookiejar.New(nil)
	if err != nil {
		panic(err)
	}

	clnt := srvr.Client()
	clnt.Jar = jar
	resp, err := clnt.Do(req)

	if err != nil {
		return "", err
	}

	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("%s", resp.Status)
	}

	clms := make(map[string]string)
	dec := json.NewDecoder(resp.Body)
	err = dec.Decode(&clms)

	if err != nil {
		return "", err
	}

	return "nothing", nil
}

func TestHandleLoginPOST(t *testing.T) {
	ts := httptest.NewTLSServer(GetAuthRoutes(servers.Author))
	defer ts.Close()

	tkn, err := ObtainToken(ts, "kong.auth", "secret", "kong.login.apply", "kong.consent.apply")

	if err != nil {
		t.Fatal(err)
		return
	}

	ut, err := ObtainUserLogin(ts, tkn, "kong.viewr", "user@fake.com", "user1pass")

	if err != nil {
		t.Error(err)
		return
	}

	log.Println(ut)
}

/*
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
}

func TestHandleLoginGET(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/login", nil)
	rr := httptest.NewRecorder()
	GetAuthRoutes(server.Author).ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatal(rr.Code, rr.Body.String())
		return
	}

	log.Println(rr.Body.String())
}
*/