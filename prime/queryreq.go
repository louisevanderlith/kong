package prime

//
type QueryRequest struct {
	Partial string
}

//ClientQuery is the response from QueryRequest
type ClientQuery struct {
	Username string
	Consent  map[string][]string
}
