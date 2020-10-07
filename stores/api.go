package stores

import (
	"encoding/json"
	"github.com/louisevanderlith/kong/tokens"
	"net/http"
)

type APIService interface {
	InspectIdentity(scope, secret string, token []byte) (tokens.Identity, error)
	FetchUserIdentity(token []byte) (tokens.UserIdentity, error)
	Whitelist(scope, secret string) ([]string, error)
}

func NewAPIService(client *http.Client, securityUrl, entityUrl string) APIService {
	return apisvc{
		client:      client,
		securityUrl: securityUrl,
		entityUrl:   entityUrl,
	}
}

type apisvc struct {
	client      *http.Client
	securityUrl string
	entityUrl   string
}

//InspectIdentity returns the Full token identity
func (c apisvc) InspectIdentity(scope, secret string, token []byte) (tokens.Identity, error) {
	return decodeIdentity(c.client, c.securityUrl+"/inspect", scope, secret, token)
}

//FetchUserIdentity return the User token identity
func (c apisvc) FetchUserIdentity(token []byte) (tokens.UserIdentity, error) {
	return decodeUserIdentity(c.client, c.entityUrl, token)
}

//Whitelist calls the Security whitelist endpoint to obtain a list of allowed Clients
func (c apisvc) Whitelist(scope, secret string) ([]string, error) {
	req, err := http.NewRequest(http.MethodGet, c.securityUrl+"/whitelist", nil)
	req.SetBasicAuth(scope, secret)

	if err != nil {
		return nil, err
	}

	resp, err := c.client.Do(req)

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
