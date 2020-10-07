package stores

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/louisevanderlith/kong/prime"
	"github.com/louisevanderlith/kong/tokens"
	"net/http"
)

func sendForToken(client *http.Client, name, secret, securityUrl string, tokenreq prime.TokenRequest) (prime.TokenResponse, error) {
	obj, err := json.Marshal(tokenreq)

	if err != nil {
		return prime.TokenResponse{}, err
	}

	req, err := http.NewRequest(http.MethodPost, securityUrl+"/token", bytes.NewBuffer(obj))

	if err != nil {
		return prime.TokenResponse{}, err
	}

	req.SetBasicAuth(name, secret)

	if err != nil {
		return prime.TokenResponse{}, err
	}

	resp, err := client.Do(req)

	if err != nil {
		return prime.TokenResponse{}, err
	}

	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return prime.TokenResponse{}, fmt.Errorf("%v", resp.StatusCode)
	}

	body := prime.TokenResponse{}
	dec := json.NewDecoder(resp.Body)
	err = dec.Decode(&body)

	return body, err
}

func decodeIdentity(client *http.Client, inspectUrl, name, secret string, token []byte) (tokens.Identity, error) {
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

	resp, err := client.Do(req)

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

func decodeUserIdentity(client *http.Client, entityUrl string, token []byte) (tokens.UserIdentity, error) {
	if len(token) == 0 {
		return nil, errors.New("token is empty")
	}

	req, err := http.NewRequest(http.MethodGet, entityUrl+"/insight", nil)
	req.Header.Set("Authorization", "Bearer "+string(token))

	if err != nil {
		return nil, err
	}

	resp, err := client.Do(req)

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
