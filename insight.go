package kong

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/louisevanderlith/kong/prime"
	"github.com/louisevanderlith/kong/tokens"
	"net/http"
)

//IdentityInsider provides the ability for Resources and Clients to inspect tokens
type IdentityInsider interface {
	ResourceInsight(token, resource, secret string) (tokens.Identity, error)
	ClientInsight(token, secret string) (tokens.Identity, error)
}

func FetchIdentity(clnt *http.Client, token []byte, inspectUrl string, name string, secret string) (tokens.Identity, error) {
	insReq := prime.QueryRequest{Token: string(token)}
	obj, err := json.Marshal(insReq)
	req, err := http.NewRequest(http.MethodPost, inspectUrl, bytes.NewBuffer(obj))
	req.SetBasicAuth(name, secret)

	if err != nil {
		return nil, err
	}

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

//UserInsider
type UserInsider interface {
	Insight(request prime.QueryRequest) (tokens.Claims, error)
}

func FetchUserIdentity(clnt *http.Client, usrToken, token []byte, managerUrl string) (tokens.UserIdentity, error) {
	if len(usrToken) == 0 {
		return nil, errors.New("user token is empty")
	}

	data := prime.QueryRequest{Token: string(usrToken)}
	bits, err := json.Marshal(data)

	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest(http.MethodPost, managerUrl+"/insight", bytes.NewBuffer(bits))
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
