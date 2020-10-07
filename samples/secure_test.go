package samples

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/louisevanderlith/kong/prime"
	"github.com/louisevanderlith/kong/tokens"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// Secure is the API for Authentication
func ObtainToken(srvr *httptest.Server, usertoken []byte, clientId, secret string, scopes map[string]bool) (string, error) {
	tknReq := prime.TokenRequest{
		UserToken: string(usertoken),
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

	if resp.StatusCode == http.StatusUnprocessableEntity {
		return "", errors.New("user login required")
	}

	if resp.StatusCode != http.StatusOK {
		return "", errors.New(strings.Replace(string(body), "\n", "", 1))
	}

	return string(body), nil
}

func ObtainInspection(srvr *httptest.Server, token, resource, secret string) (tokens.Claims, error) {
	insReq := prime.QueryRequest{Token: token}
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

	clms := tokens.EmptyClaims()
	dec := json.NewDecoder(resp.Body)
	err = dec.Decode(&clms)

	if err != nil {
		return nil, err
	}

	return clms, nil
}

func ObtainInfo(srvr *httptest.Server, token, clientId, secret string) (tokens.Claims, error) {
	insReq := prime.QueryRequest{Token: token}
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

	clms := tokens.EmptyClaims()
	dec := json.NewDecoder(resp.Body)
	err = dec.Decode(&clms)

	if err != nil {
		return nil, err
	}

	return clms, nil
}

func TestHandleTokenPOST_NoUserRequired(t *testing.T) {
	ts := httptest.NewServer(GetSecureRoutes())
	defer ts.Close()

	_, err := ObtainToken(ts, []byte{}, "kong.viewr", "secret", map[string]bool{"api.profile.view": true})

	if err != nil {
		t.Error(err)
		return
	}
}

func TestHandleTokenPOST_UserRequired(t *testing.T) {
	ts := httptest.NewServer(GetSecureRoutes())
	defer ts.Close()
	_, err := ObtainToken(ts, []byte{}, "kong.viewr", "secret", map[string]bool{"api.user.view": true})

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
	ts := httptest.NewServer(GetSecureRoutes())
	defer ts.Close()

	tkn, err := ObtainToken(ts, []byte{}, "kong.viewr", "secret", map[string]bool{"api.profile.view": true})

	if err != nil {
		t.Fatal("Obtain Token Error", err)
		return
	}

	clms, err := ObtainInspection(ts, tkn, "api.profile.view", "secret")

	if err != nil {
		t.Fatal("Obtain Inspection Error", err)
		return
	}

	act := clms.GetClaimString(tokens.KongProfile)
	if act != "kong" {
		t.Error("unexpected claim value", act)
	}
}

func TestHandleInfoPOST(t *testing.T) {
	ts := httptest.NewServer(GetSecureRoutes())
	defer ts.Close()

	tkn, err := ObtainToken(ts, []byte{}, "kong.viewr", "secret", map[string]bool{"api.profile.view": true})

	if err != nil {
		t.Fatal("Obtain Token Error", err)
		return
	}

	clms, err := ObtainInfo(ts, tkn, "kong.viewr", "secret")

	if err != nil {
		t.Fatal("Obtain Info Error", err)
		return
	}

	t.Log(clms)
	act := clms.GetClaimString(tokens.KongProfile)
	if act != "kong" {
		t.Error("unexpected claim value", act)
	}
}
