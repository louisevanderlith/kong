package prime

type QueryRequest struct {
	Token  string
	Claims map[string]bool
}

//ClientQuery is the response from QueryRequest
type ClientQuery struct {
	Username string
	Consent  map[string][]string
}
