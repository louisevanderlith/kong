package kong

//Scoper can any object that is able to Provide claim values
type Scoper interface {
	ProvideClaim(claim string) string
}
