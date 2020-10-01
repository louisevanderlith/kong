package samples

import (
	"github.com/gorilla/mux"
	"github.com/louisevanderlith/kong/middle"
	"github.com/louisevanderlith/kong/samples/handlers/api"
	"github.com/louisevanderlith/kong/samples/handlers/auth"
	"github.com/louisevanderlith/kong/samples/handlers/entity"
	"github.com/louisevanderlith/kong/samples/handlers/secure"
	"github.com/louisevanderlith/kong/samples/handlers/viewr"
	"net/http"
)

//GetAuthRoutes returns a router for the Auth UI
func GetAuthRoutes() http.Handler {
	r := mux.NewRouter()

	r.HandleFunc("/login", auth.HandleLoginGET).Methods(http.MethodGet)
	r.HandleFunc("/login", auth.HandleLoginPOST).Methods(http.MethodPost)
	r.HandleFunc("/consent", auth.HandleConsentGET).Queries("client", "{client}", "callback", "{callback}", "state", "{state}").Methods(http.MethodGet)
	r.HandleFunc("/consent", auth.HandleConsentGET).Queries("client", "{client}", "state", "{state}", "partial", "{partial}").Methods(http.MethodGet)
	r.HandleFunc("/consent", auth.HandleConsentPOST).Methods(http.MethodPost)

	r.Queries("client", "{client}", "callback", "{callback}")
	return r
}

//GetManagerRoutes returns a router for the User API
func GetManagerRoutes(clnt *http.Client, securityUrl string) http.Handler {
	r := mux.NewRouter()

	ins := middle.NewResourceInspector(clnt, securityUrl, "")
	r.HandleFunc("/login", ins.Middleware("entity.login.apply", "secret", entity.HandleLoginPOST)).Methods(http.MethodPost)
	r.HandleFunc("/consent", ins.Middleware("entity.consent.apply", "secret", entity.HandleConsentPOST)).Methods(http.MethodPost)
	r.HandleFunc("/insight", ins.Middleware("entity.user.view", "secret", entity.HandleInsightPost)).Methods(http.MethodPost)

	return r
}

//GetSecureRoutes returns a router for the Security Server
func GetSecureRoutes(securer middle.Security) http.Handler {
	r := mux.NewRouter()

	r.HandleFunc("/token", secure.HandleTokenPOST).Methods(http.MethodPost)

	r.HandleFunc("/query/{client:[a-z]+}", middle.InternalMiddleware(securer, "kong.client.query", "secret", secure.HandleClientQueryGET)).Methods(http.MethodGet)

	r.HandleFunc("/inspect", secure.HandleInspectPOST).Methods(http.MethodPost)
	r.HandleFunc("/info", secure.HandleInfoPOST).Methods(http.MethodPost)

	return r
}

//GetViewrRoutes returns a router for the Sample UI
func GetViewrRoutes(clnt *http.Client, securityUrl, authorityUrl string) http.Handler {
	r := mux.NewRouter()

	clntInsp := middle.NewClientInspector("client.viewr", "secret", clnt, securityUrl, authorityUrl)
	appMdl := clntInsp.Middleware(viewr.HandleIndexGET, nil)
	r.HandleFunc("/", appMdl).Methods(http.MethodGet)
	r.HandleFunc("/callback", viewr.HandleCallbackGET).Queries("ut", "{ut:[a-zA-Z0-9]+}").Methods(http.MethodGet)

	return r
}

//GetApiRoutes returns a router for the Sample Resource
func GetApiRoutes(clnt *http.Client, securityUrl, managerUrl string) http.Handler {
	r := mux.NewRouter()

	ins := middle.NewResourceInspector(clnt, securityUrl, "")
	profMdl := ins.Middleware("api.profile.view", "secret", api.HandleProfileGET)
	r.HandleFunc("/profile", profMdl).Methods(http.MethodGet)
	usrMdl := ins.Middleware("api.user.view", "secret", api.HandleUserGET)
	r.HandleFunc("/user", usrMdl).Methods(http.MethodGet)

	return r
}
