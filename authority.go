package kong

import (
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/louisevanderlith/kong/prime"
	"net/http"
)

// Authority provides functions for connecting Security & User Manager functions
type Authority interface {
	ClientQuery(request prime.QueryRequest) (string, map[string][]string, error)
	GiveConsent(request prime.ConsentRequest) (string, error)
	AuthenticateUser(request prime.LoginRequest) (string, error)
}

type authority struct {
	clnt        *http.Client
	tkn         string
	securityUrl string
	managerUrl  string
}

//NewAuthority returns a client which can call the Secure & Entity server's API
func NewAuthority(client *http.Client, securityUrl, managerUrl, authTkn string) Authority {
	return authority{clnt: client, tkn: authTkn, securityUrl: securityUrl, managerUrl: managerUrl}
}

//ClientQuery returns the username and the client's required claims
func (a authority) ClientQuery(request prime.QueryRequest) (string, map[string][]string, error) {
	bits, err := json.Marshal(request)

	if err != nil {
		return "", nil, err
	}

	req, err := http.NewRequest(http.MethodPost, a.securityUrl+"/query", bytes.NewBuffer(bits))
	req.Header.Set("Authorization", "Bearer "+a.tkn)

	if err != nil {
		return "", nil, err
	}

	resp, err := a.clnt.Do(req)

	if err != nil {
		return "", nil, err
	}

	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", nil, fmt.Errorf("%s", resp.Status)
	}

	qry := prime.ClientQuery{}
	dec := json.NewDecoder(resp.Body)
	err = dec.Decode(&qry)

	if err != nil {
		return "", nil, err
	}

	return qry.Username, qry.Consent, nil
}

//GiveConsent returns a signed user token
func (a authority) GiveConsent(request prime.ConsentRequest) (string, error) {
	bits, err := json.Marshal(request)

	if err != nil {
		return "", err
	}

	req, err := http.NewRequest(http.MethodPost, a.managerUrl+"/consent", bytes.NewBuffer(bits))
	req.Header.Set("Authorization", "Bearer "+a.tkn)

	if err != nil {
		return "", err
	}

	resp, err := a.clnt.Do(req)

	if err != nil {
		return "", err
	}

	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("%s", resp.Status)
	}

	qry := ""
	dec := json.NewDecoder(resp.Body)
	err = dec.Decode(&qry)

	if err != nil {
		return "", err
	}

	return qry, nil
}

//AuthenticateUser returns a signed partial user token
func (a authority) AuthenticateUser(request prime.LoginRequest) (string, error) {
	bits, err := json.Marshal(request)

	if err != nil {
		return "", err
	}

	req, err := http.NewRequest(http.MethodPost, a.managerUrl+"/login", bytes.NewBuffer(bits))
	req.Header.Set("Authorization", "Bearer "+a.tkn)

	if err != nil {
		return "", err
	}

	resp, err := a.clnt.Do(req)

	if err != nil {
		return "", err
	}

	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("%s", resp.Status)
	}

	qry := ""
	dec := json.NewDecoder(resp.Body)
	err = dec.Decode(&qry)

	if err != nil {
		return "", err
	}

	return qry, nil
}
