package kong

import (
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/louisevanderlith/kong/middle"
	"github.com/louisevanderlith/kong/prime"
	"net/http"
)

// Authority provides functions for connecting Security & User Manager functions
type Authority interface {
	ClientQuery(client string) ([]prime.Resource, error)
	GiveConsent(request prime.QueryRequest) (string, error)
	AuthenticateUser(request prime.LoginRequest) (string, error)
}

type authority struct {
	clnt        *http.Client
	id          string
	secret      string
	securityUrl string
	managerUrl  string
}

//NewAuthority returns a client which can call the Secure & Entity server's API
func NewAuthority(client *http.Client, securityUrl, managerUrl, id, secret string) Authority {
	return authority{clnt: client, id: id, secret: secret, securityUrl: securityUrl, managerUrl: managerUrl}
}

//ClientQuery returns the username and the client's required claims
func (a authority) ClientQuery(client string) ([]prime.Resource, error) {
	tkn, err := middle.FetchToken(http.DefaultClient, a.securityUrl, a.id, a.secret, "", map[string]bool{"secure.client.query": true})

	if err != nil {
		return nil, err
	}

	fullUrl := fmt.Sprintf("%s/query/%s", a.securityUrl, client)
	req, err := http.NewRequest(http.MethodGet, fullUrl, nil)
	req.Header.Set("Authorization", "Bearer "+tkn)

	if err != nil {
		return nil, err
	}

	resp, err := a.clnt.Do(req)

	if err != nil {
		return nil, err
	}

	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s", resp.Status)
	}

	var qry []prime.Resource
	dec := json.NewDecoder(resp.Body)
	err = dec.Decode(&qry)

	if err != nil {
		return nil, err
	}

	return qry, nil
}

//GiveConsent returns a signed user token
func (a authority) GiveConsent(request prime.QueryRequest) (string, error) {
	tkn, err := middle.FetchToken(http.DefaultClient, a.securityUrl, a.id, a.secret, "", map[string]bool{"entity.consent.apply": true})

	if err != nil {
		return "", err
	}

	bits, err := json.Marshal(request)

	if err != nil {
		return "", err
	}

	req, err := http.NewRequest(http.MethodPost, a.managerUrl+"/consent", bytes.NewBuffer(bits))
	req.Header.Set("Authorization", "Bearer "+tkn)

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
	tkn, err := middle.FetchToken(http.DefaultClient, a.securityUrl, a.id, a.secret, "", map[string]bool{"entity.login.apply": true})

	if err != nil {
		return "", err
	}

	bits, err := json.Marshal(request)

	if err != nil {
		return "", err
	}

	req, err := http.NewRequest(http.MethodPost, a.managerUrl+"/login", bytes.NewBuffer(bits))
	req.Header.Set("Authorization", "Bearer "+tkn)

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
