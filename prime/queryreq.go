package prime

type QueryRequest struct {
	Token  string
	Claims interface{}
}

func (q QueryRequest) GetRequirements() (map[string]bool, error) {
	val, isShap := q.Claims.(map[string]bool)

	if isShap {
		return val, nil
	}

	m := q.Claims.(map[string]interface{})

	result := make(map[string]bool)

	for k, v := range m {
		result[k] = v.(bool)
	}

	return result, nil
}

//ClientQuery is the response from QueryRequest
type ClientQuery struct {
	Username string
	Consent  map[string][]string
}
