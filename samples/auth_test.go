package samples

import (
	"bytes"
	"encoding/json"
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

	tkn, err := ObtainToken(ts, "kong.auth", "secret", "entity.login.apply", "entity.consent.apply")

	if err != nil {
		t.Fatal("Obtain Token Error", err)
		return
	}

	ut, err := ObtainUserLogin(tm, tkn, "kong.auth", "user@fake.com", "user1pass")

	if err != nil {
		t.Error("Obtain Login Error", err)
		return
	}

	if len(ut) == 0 {
		t.Error("user token is empty")
	}
}
