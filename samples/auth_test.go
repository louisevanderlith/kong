package samples

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/louisevanderlith/kong/samples/server"
	"io/ioutil"
	"log"
	http "net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/louisevanderlith/kong/prime"
	"github.com/louisevanderlith/kong/samples/controllers"
	"github.com/louisevanderlith/kong/tokens"
)

func ObtainToken(srvr *httptest.Server, clientId, secret string, scopes ...string) (string, error) {
	tknReq := prime.TokenReq{
		UserToken: make(tokens.Claims),
		Scopes:    scopes,
	}
	obj, err := json.Marshal(tknReq)

	if err != nil {
		return "", err
	}

	req, err := http.NewRequest(http.MethodPost, srvr.URL+"/token", bytes.NewBuffer(obj))
	req.SetBasicAuth(clientId, secret)

	if err != nil {
		return "", err
	}

	resp, err := srvr.Client().Do(req)

	if err != nil {
		return "", err
	}

	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if len(body) == 0 {
		return "", errors.New("no response")
	}

	if resp.StatusCode != http.StatusOK {
		return "", errors.New(strings.Replace(string(body), "\n", "", 1))
	}

	return string(body), nil
}

func ObtainInspection(srvr *httptest.Server, token, resource, secret string) (map[string]string, error) {
	insReq := prime.InspectReq{AccessCode: token}
	obj, err := json.Marshal(insReq)

	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest(http.MethodPost, srvr.URL+"/inspect", bytes.NewBuffer(obj))
	req.SetBasicAuth(resource, secret)

	if err != nil {
		return nil, err
	}

	resp, err := srvr.Client().Do(req)

	if err != nil {
		return nil, err
	}

	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s", resp.Status)
	}

	clms := make(map[string]string)
	dec := json.NewDecoder(resp.Body)
	err = dec.Decode(&clms)

	if err != nil {
		return nil, err
	}

	return clms, nil
}

func ObtainInfo(srvr *httptest.Server, token, clientId, secret string) (map[string]string, error) {
	insReq := prime.InspectReq{AccessCode: token}
	obj, err := json.Marshal(insReq)

	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest(http.MethodPost, srvr.URL+"/info", bytes.NewBuffer(obj))
	req.SetBasicAuth(clientId, secret)

	if err != nil {
		return nil, err
	}

	resp, err := srvr.Client().Do(req)

	if err != nil {
		return nil, err
	}

	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s", resp.Status)
	}

	clms := make(map[string]string)
	dec := json.NewDecoder(resp.Body)
	err = dec.Decode(&clms)

	if err != nil {
		return nil, err
	}

	return clms, nil
}

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

func TestHandleTokenPOST_NoUserRequired(t *testing.T) {
	ts := httptest.NewServer(GetAuthRoutes(server.Author))
	defer ts.Close()
	_, err := ObtainToken(ts, "kong.viewr", "secret", "api.profile.view")
	if err != nil {
		t.Error(err)
		return
	}
}

func TestHandleTokenPOST_UserRequired(t *testing.T) {
	ts := httptest.NewServer(GetAuthRoutes(server.Author))
	defer ts.Close()
	_, err := ObtainToken(ts, "kong.viewr", "secret", "api.user.view")
	if err == nil {
		t.Error("expecting error")
		return
	}

	if err.Error() != "user login required" {
		t.Error("ERROR", err)
		return
	}
}

func TestHandleInspectPOST(t *testing.T) {
	ts := httptest.NewServer(GetAuthRoutes(server.Author))
	defer ts.Close()

	tkn, err := ObtainToken(ts, "kong.viewr", "secret", "api.profile.view")

	if err != nil {
		t.Fatal(err)
		return
	}

	clms, err := ObtainInspection(ts, tkn, "api.profile.view", "secret")

	if err != nil {
		t.Fatal(err)
		return
	}

	if clms["profile.name"] != "kong" {
		t.Error("unexpected claim value", clms["profile.name"])
	}
}

func TestHandleInfoPOST(t *testing.T) {
	ts := httptest.NewServer(GetAuthRoutes(server.Author))
	defer ts.Close()

	tkn, err := ObtainToken(ts, "kong.viewr", "secret", "api.profile.view")

	if err != nil {
		t.Fatal(err)
		return
	}

	clms, err := ObtainInfo(ts, tkn, "kong.viewr", "secret")

	if err != nil {
		t.Fatal(err)
		return
	}
	t.Log(clms)
	if clms["kong.profile"] != "kong" {
		t.Error("unexpected claim value", clms["kong.profile"])
	}
}

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

func TestHandleLoginPOST(t *testing.T) {
	ts := httptest.NewTLSServer(GetAuthRoutes(server.Author))
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
