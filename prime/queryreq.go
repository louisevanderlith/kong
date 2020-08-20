package prime

import "errors"

type QueryRequest struct {
	Token  string
	Claims interface{}
}

func (q QueryRequest) GetRequirements() (map[string]bool, error) {
	val, ok := q.Claims.(map[string]interface{})

	if !ok {
		return nil, errors.New("claims incorrect type")
	}

	result := make(map[string]bool)

	for k, v := range val {
		b, isBool := v.(bool)

		if !isBool {
			return nil, errors.New("claims value incorrect type")
		}

		result[k] = b
	}

	return result, nil
}

//ClientQuery is the response from QueryRequest
type ClientQuery struct {
	Username string
	Consent  map[string][]string
}
