package inspectors

import (
	"bytes"
	"encoding/json"
	"github.com/louisevanderlith/kong/prime"
	"net/http"
)

type remoteInspector struct {
	authUrl string
}

func NewRemoteInspector(authUrl string) Inspector {
	return remoteInspector{authUrl: authUrl}
}

func (i remoteInspector) Exchange(rawtoken, scope, secret string) (map[string]string, error) {
	insReq := prime.InspectReq{AccessCode: rawtoken}
	obj, err := json.Marshal(insReq)
	req, err := http.NewRequest(http.MethodPost, i.authUrl+"/inspect", bytes.NewBuffer(obj))
	req.SetBasicAuth(scope, secret)

	if err != nil {
		return nil, err
	}

	defer req.Body.Close()
	
	clms := make(map[string]string)
	dec := json.NewDecoder(req.Body)
	err = dec.Decode(&clms)

	if err != nil {
		return nil, err
	}

	return clms, nil
}
