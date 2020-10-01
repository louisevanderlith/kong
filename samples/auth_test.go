package samples

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/louisevanderlith/kong/prime"
	"github.com/louisevanderlith/kong/samples/servers/secure"
	"io/ioutil"
	http "net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"testing"
)

// Auth is the UI for Authentication
func ObtainUserLogin(manServer *httptest.Server, secServer *httptest.Server, clientId, username, password string) (string, error) {
	insReq := prime.LoginRequest{
		Client:   clientId,
		Username: username,
		Password: password,
	}

	obj, err := json.Marshal(insReq)

	if err != nil {
		return "", err
	}

	authtkn, err := ObtainToken(secServer, []byte{}, "kong.auth", "secret", map[string]bool{"entity.login.apply": true, "entity.consent.apply": true})

	if err != nil {
		return "", errors.New("unable to obtain auth token")
	}

	req, err := http.NewRequest(http.MethodPost, manServer.URL+"/login", bytes.NewBuffer(obj))
	req.Header.Set("Authorization", "Bearer "+authtkn)

	if err != nil {
		return "", err
	}

	jar, err := cookiejar.New(nil)
	if err != nil {
		panic(err)
	}

	clnt := manServer.Client()
	clnt.Jar = jar
	resp, err := clnt.Do(req)

	if err != nil {
		return "", err
	}

	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("%s", resp.Status)
	}

	bits, err := ioutil.ReadAll(resp.Body)

	if err != nil {
		return "", err
	}

	return string(bits), nil
}

func TestHandleLoginPOST(t *testing.T) {
	ts := httptest.NewTLSServer(GetSecureRoutes(secure.Security))
	defer ts.Close()

	tm := httptest.NewTLSServer(GetManagerRoutes(ts.Client(), ts.URL))
	defer tm.Close()

	ut, err := ObtainUserLogin(tm, ts, "kong.viewr", "user@fake.com", "user1pass")

	if err != nil {
		t.Error("Obtain Login Error", err)
		return
	}

	if len(ut) == 0 {
		t.Error("user token is empty")
	}
}

func TestHandleConsentGET_NoUser(t *testing.T) {
	ts := httptest.NewTLSServer(GetSecureRoutes(secure.Security))
	defer ts.Close()

	tm := httptest.NewTLSServer(GetManagerRoutes(ts.Client(), ts.URL))
	defer tm.Close()

	ut, err := ObtainUserLogin(tm, ts, "kong.viewr", "user@fake.com", "user1pass")

	if err != nil {
		t.Error("Obtain Login Error", err)
		return
	}

	if len(ut) == 0 {
		t.Error("user token is empty")
	}
}

func TestHandleConsentGET_User(t *testing.T) {
	ts := httptest.NewTLSServer(GetSecureRoutes(secure.Security))
	defer ts.Close()

	tm := httptest.NewTLSServer(GetManagerRoutes(ts.Client(), ts.URL))
	defer tm.Close()

	ut, err := ObtainUserLogin(tm, ts, "kong.viewr", "user@fake.com", "user1pass")

	if err != nil {
		t.Error("Obtain Login Error", err)
		return
	}

	if len(ut) == 0 {
		t.Error("user token is empty")
	}
}
