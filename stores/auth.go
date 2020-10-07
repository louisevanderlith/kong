package stores

import (
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/louisevanderlith/kong/prime"
	"net/http"
)

type AuthorityService interface {
	RequestToken(tokenreq prime.TokenRequest) (prime.TokenResponse, error)
	QueryClient(client, token string) (prime.ClaimConsent, error)
	AuthenticateUser(request prime.LoginRequest, token string) (string, error)
	ApplyConsent(request prime.QueryRequest, token string) (string, error)
}

func NewAuthService(client *http.Client, securityUrl, entityUrl, name, secret string) AuthorityService {
	return authscv{
		client:      client,
		securityUrl: securityUrl,
		entityUrl:   entityUrl,
		name:        name,
		secret:      secret,
	}
}

type authscv struct {
	client      *http.Client
	securityUrl string
	entityUrl   string
	name        string
	secret      string
}

func (a authscv) RequestToken(tokenreq prime.TokenRequest) (prime.TokenResponse, error) {
	return sendForToken(a.client, a.name, a.secret, a.securityUrl, tokenreq)
}

func (a authscv) QueryClient(client, token string) (prime.ClaimConsent, error) {
	fullUrl := fmt.Sprintf("%s/query/%s", a.securityUrl, client)
	req, err := http.NewRequest(http.MethodGet, fullUrl, nil)
	req.Header.Set("Authorization", "Bearer "+token)

	if err != nil {
		return prime.ClaimConsent{}, err
	}

	resp, err := a.client.Do(req)

	if err != nil {
		return prime.ClaimConsent{}, err
	}

	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return prime.ClaimConsent{}, fmt.Errorf("%s", resp.Status)
	}

	qry := prime.ClaimConsent{}
	dec := json.NewDecoder(resp.Body)
	err = dec.Decode(&qry)

	return qry, err
}

func (a authscv) AuthenticateUser(request prime.LoginRequest, token string) (string, error) {
	bits, err := json.Marshal(request)

	if err != nil {
		return "", err
	}

	req, err := http.NewRequest(http.MethodPost, a.entityUrl+"/login", bytes.NewBuffer(bits))
	req.Header.Set("Authorization", "Bearer "+token)

	if err != nil {
		return "", err
	}

	resp, err := a.client.Do(req)

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

func (a authscv) ApplyConsent(request prime.QueryRequest, token string) (string, error) {
	bits, err := json.Marshal(request)

	if err != nil {
		return "", err
	}

	req, err := http.NewRequest(http.MethodPost, a.entityUrl+"/consent", bytes.NewBuffer(bits))
	req.Header.Set("Authorization", "Bearer "+token)

	if err != nil {
		return "", err
	}

	resp, err := a.client.Do(req)

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
