package kong

import (
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/louisevanderlith/kong/prime"
	"net/http"
)

// Securer provides functions for the User interface of kong
type Securer interface {
	ClientQuery(request prime.QueryRequest) (string, map[string][]string, error)
	GiveConsent(request prime.ConsentRequest) (string, error)
	AuthenticateUser(request prime.LoginRequest) (string, error)
}

type security struct {
	clnt *http.Client
	tkn  string
	url  string
}

//NewSecurity returns a client which can call the Authentication server's API
func NewSecurity(client *http.Client, authURL, authTkn string) Securer {
	return security{clnt: client, tkn: authTkn, url: authURL}
}

//ClientQuery returns the username and the client's required claims
func (s security) ClientQuery(request prime.QueryRequest) (string, map[string][]string, error) {
	bits, err := json.Marshal(request)

	if err != nil {
		return "", nil, err
	}

	req, err := http.NewRequest(http.MethodPost, s.url+"/query", bytes.NewBuffer(bits))
	req.Header.Set("Authorization", "Bearer "+s.tkn)

	if err != nil {
		return "", nil, err
	}

	resp, err := s.clnt.Do(req)

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
func (s security) GiveConsent(request prime.ConsentRequest) (string, error) {
	bits, err := json.Marshal(request)

	if err != nil {
		return "", err
	}

	req, err := http.NewRequest(http.MethodPost, s.url+"/consent", bytes.NewBuffer(bits))
	req.Header.Set("Authorization", "Bearer "+s.tkn)

	if err != nil {
		return "", err
	}

	resp, err := s.clnt.Do(req)

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
func (s security) AuthenticateUser(request prime.LoginRequest) (string, error) {
	bits, err := json.Marshal(request)

	if err != nil {
		return "", err
	}

	req, err := http.NewRequest(http.MethodPost, s.url+"/login", bytes.NewBuffer(bits))
	req.Header.Set("Authorization", "Bearer "+s.tkn)

	if err != nil {
		return "", err
	}

	resp, err := s.clnt.Do(req)

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
