package middle

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/louisevanderlith/kong/prime"
	"github.com/louisevanderlith/kong/tokens"
	"io/ioutil"
	"net/http"
	"strings"
)

//GetBearerToken returns the Bearer Authorization header
func GetBearerToken(r *http.Request) (string, error) {
	reqToken := r.Header.Get("Authorization")

	if len(reqToken) == 0 {
		return "", errors.New("header length invalid")
	}

	prefix := "Bearer "

	if !strings.HasPrefix(reqToken, prefix) {
		return "", errors.New("bearer not found")
	}

	token := reqToken[len(prefix):]

	if len(token) == 0 {
		return "", errors.New("token length invalid")
	}

	return token, nil
}

//FetchToken calls the Security Token endpoint to obtain a Client Token
func FetchToken(clnt *http.Client, securityUrl, clientId, secret, userToken string, scopes map[string]bool) (string, error) {
	tknReq := prime.QueryRequest{
		Token:  userToken,
		Claims: scopes,
	}
	obj, err := json.Marshal(tknReq)

	if err != nil {
		return "", err
	}

	req, err := http.NewRequest(http.MethodPost, securityUrl+"/token", bytes.NewBuffer(obj))

	if err != nil {
		return "", err
	}

	req.SetBasicAuth(clientId, secret)

	if err != nil {
		return "", err
	}

	resp, err := clnt.Do(req)

	if err != nil {
		return "", err
	}

	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("%v", resp.StatusCode)
	}

	body, err := ioutil.ReadAll(resp.Body)
	if len(body) == 0 {
		return "", errors.New("no response")
	}

	return string(body), nil
}

//FetchIdentity returns the Full token identity
func FetchIdentity(clnt *http.Client, token []byte, inspectUrl string, name string, secret string) (tokens.Identity, error) {
	insReq := prime.QueryRequest{Token: string(token)}
	obj, err := json.Marshal(insReq)

	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest(http.MethodPost, inspectUrl, bytes.NewBuffer(obj))

	if err != nil {
		return nil, err
	}

	req.SetBasicAuth(name, secret)

	resp, err := clnt.Do(req)

	if err != nil {
		return nil, err
	}

	defer resp.Body.Close()

	clms := tokens.EmptyIdentity()
	dec := json.NewDecoder(resp.Body)
	err = dec.Decode(&clms)

	if err != nil {
		return nil, err
	}

	return clms, nil
}

//FetchUserIdentity return the User token identity
func FetchUserIdentity(clnt *http.Client, token []byte, managerUrl string) (tokens.UserIdentity, error) {
	if len(token) == 0 {
		return nil, errors.New("token is empty")
	}

	req, err := http.NewRequest(http.MethodGet, managerUrl+"/insight", nil)
	req.Header.Set("Authorization", "Bearer "+string(token))

	if err != nil {
		return nil, err
	}

	resp, err := clnt.Do(req)

	if err != nil {
		return nil, err
	}

	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s", resp.Status)
	}

	result := tokens.EmptyUserIdentity()
	dec := json.NewDecoder(resp.Body)
	err = dec.Decode(&result)

	if err != nil {
		return nil, err
	}

	return result, nil
}

//Whitelist calls the Security whitelist endpoint to obtain a list of allowed Clients
func Whitelist(clnt *http.Client, securityUrl, name, secret string) ([]string, error) {
	req, err := http.NewRequest(http.MethodGet, securityUrl+"/whitelist", nil)
	req.SetBasicAuth(name, secret)

	if err != nil {
		return nil, err
	}

	resp, err := clnt.Do(req)

	if err != nil {
		return nil, err
	}

	defer resp.Body.Close()

	var wht []string
	dec := json.NewDecoder(resp.Body)
	err = dec.Decode(&wht)

	if err != nil {
		return nil, err
	}

	return wht, nil
}
