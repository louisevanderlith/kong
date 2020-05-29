package samples

import (
	"github.com/gorilla/mux"
	"github.com/louisevanderlith/kong"
	"github.com/louisevanderlith/kong/samples/handlers/api"
	"github.com/louisevanderlith/kong/samples/handlers/auth"
	"github.com/louisevanderlith/kong/samples/handlers/secure"
	"github.com/louisevanderlith/kong/samples/handlers/viewr"
	"net/http"
)

//GetAuthRoutes returns a router for the Secure UI
func GetAuthRoutes() http.Handler {
	r := mux.NewRouter()

	r.HandleFunc("/login", auth.HandleLoginGET).Methods(http.MethodGet)
	r.HandleFunc("/login", auth.HandleLoginPOST).Methods(http.MethodPost)
	r.HandleFunc("/consent", auth.HandleConsentGET).Methods(http.MethodGet)
	r.HandleFunc("/consent", auth.HandleConsentPOST).Methods(http.MethodPost)

	r.Queries("client", "{client}", "callback", "{callback}")
	return r
}

//GetSecureRoutes returns a router for the Authorization Server
func GetSecureRoutes(authr kong.Author) http.Handler {
	r := mux.NewRouter()

	r.HandleFunc("/token", secure.HandleTokenPOST).Methods(http.MethodPost)

	r.HandleFunc("/login", kong.InternalMiddleware(authr, "kong.login.apply", "secret", secure.HandleLoginPOST)).Methods(http.MethodPost)
	r.HandleFunc("/consent", kong.InternalMiddleware(authr, "kong.consent.apply", "secret", secure.HandleConsentPOST)).Methods(http.MethodPost)
	r.HandleFunc("/query", kong.InternalMiddleware(authr, "kong.client.query", "secret", secure.HandleClientQueryPOST)).Methods(http.MethodPost)

	r.HandleFunc("/inspect", secure.HandleInspectPOST).Methods(http.MethodPost)
	r.HandleFunc("/info", secure.HandleInfoPOST).Methods(http.MethodPost)

	return r
}

func GetViewrRoutes(clnt *http.Client, authUrl, secureUrl string) http.Handler {
	r := mux.NewRouter()

	appMdl := kong.ClientMiddleware(clnt, "client.viewr", "secret", secureUrl, authUrl, viewr.HandleIndexGET)
	r.HandleFunc("/", appMdl).Methods(http.MethodGet)
	r.HandleFunc("/callback", viewr.HandleCallbackGET).Queries("ut", "{ut:[a-zA-Z0-9]+}").Methods(http.MethodGet)

	return r
}

func GetApiRoutes(authUrl string) http.Handler {
	r := mux.NewRouter()

	profMdl := kong.ResourceMiddleware("api.profile.view", "secret", authUrl, api.HandleProfileGET)
	r.HandleFunc("/profile", profMdl).Methods(http.MethodGet)
	usrMdl := kong.ResourceMiddleware("api.user.view", "secret", authUrl, api.HandleUserGET)
	r.HandleFunc("/user", usrMdl).Methods(http.MethodGet)

	return r
}
