package samples

import (
	"github.com/gorilla/mux"
	"github.com/louisevanderlith/kong"
	"github.com/louisevanderlith/kong/samples/handlers/api"
	"github.com/louisevanderlith/kong/samples/handlers/auth"
	"github.com/louisevanderlith/kong/samples/handlers/entity"
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

func GetManagerRoutes(securityUrl string) http.Handler {
	r := mux.NewRouter()

	r.HandleFunc("/login", kong.ResourceMiddleware("kong.login.apply", "secret", securityUrl, entity.HandleLoginPOST)).Methods(http.MethodPost)
	r.HandleFunc("/consent", kong.ResourceMiddleware("kong.consent.apply", "secret", securityUrl, entity.HandleConsentPOST)).Methods(http.MethodPost)

	return r
}

//GetSecureRoutes returns a router for the Authorization Server
func GetSecureRoutes(securer kong.Security) http.Handler {
	r := mux.NewRouter()

	r.HandleFunc("/token", secure.HandleTokenPOST).Methods(http.MethodPost)

	r.HandleFunc("/query", kong.InternalMiddleware(securer, "kong.client.query", "secret", entity.HandleClientQueryPOST)).Methods(http.MethodPost)

	r.HandleFunc("/inspect", secure.HandleInspectPOST).Methods(http.MethodPost)
	r.HandleFunc("/info", secure.HandleInfoPOST).Methods(http.MethodPost)

	return r
}

func GetViewrRoutes(clnt *http.Client, securityUrl, authorityUrl string) http.Handler {
	r := mux.NewRouter()

	appMdl := kong.ClientMiddleware(clnt, "client.viewr", "secret", securityUrl, authorityUrl, viewr.HandleIndexGET)
	r.HandleFunc("/", appMdl).Methods(http.MethodGet)
	r.HandleFunc("/callback", viewr.HandleCallbackGET).Queries("ut", "{ut:[a-zA-Z0-9]+}").Methods(http.MethodGet)

	return r
}

func GetApiRoutes(securityUrl string) http.Handler {
	r := mux.NewRouter()

	profMdl := kong.ResourceMiddleware("api.profile.view", "secret", securityUrl, api.HandleProfileGET)
	r.HandleFunc("/profile", profMdl).Methods(http.MethodGet)
	usrMdl := kong.ResourceMiddleware("api.user.view", "secret", securityUrl, api.HandleUserGET)
	r.HandleFunc("/user", usrMdl).Methods(http.MethodGet)

	return r
}
