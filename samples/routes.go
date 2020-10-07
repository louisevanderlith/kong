package samples

import (
	"github.com/gorilla/mux"
	"github.com/louisevanderlith/droxolite/drx"
	"github.com/louisevanderlith/kong/authmanager"
	"github.com/louisevanderlith/kong/entitymanager"
	"github.com/louisevanderlith/kong/fakes"
	"github.com/louisevanderlith/kong/middle"
	"github.com/louisevanderlith/kong/samples/handlers/api"
	"github.com/louisevanderlith/kong/samples/handlers/viewr"
	"github.com/louisevanderlith/kong/securitymanager"
	"github.com/louisevanderlith/kong/stores"
	"net/http"
)

//GetAuthRoutes returns a router for the Auth UI
func GetAuthRoutes(client *http.Client, securityUrl, entityUrl, name, secret string) http.Handler {
	r := mux.NewRouter()

	tmpl, err := drx.LoadTemplate("./views")

	if err != nil {
		panic(err)
	}

	authsvc := stores.NewAuthService(client, securityUrl, entityUrl, name, secret)
	authmanager.InitializeManager(authsvc, true)
	r.HandleFunc("/login", authmanager.LoginGETHandler(tmpl)).Methods(http.MethodGet)
	r.HandleFunc("/login", authmanager.HandleLoginPOST).Methods(http.MethodPost)
	r.HandleFunc("/consent", authmanager.InitialConsentHandler).Queries("client", "{client}", "callback", "{callback}", "state", "{state}").Methods(http.MethodGet)
	r.HandleFunc("/consent", authmanager.UserConsentHandler(tmpl)).Queries("client", "{client}", "state", "{state}", "partial", "{partial}").Methods(http.MethodGet)
	r.HandleFunc("/consent", authmanager.ConsentPOSTHandler).Methods(http.MethodPost)

	return r
}

//GetEntityRoutes returns a router for the User API
func GetEntityRoutes(clnt *http.Client, securityUrl string) http.Handler {
	r := mux.NewRouter()

	store := fakes.NewFakeUserStore()
	entitymanager.InitializeManager(store)

	svc := stores.NewAPIService(clnt, securityUrl, "")
	mw := middle.NewResourceInspector(svc)
	r.HandleFunc("/login", mw.Lock("entity.login.apply", "secret", entitymanager.LoginPOSTHandler)).Methods(http.MethodPost)
	r.HandleFunc("/consent", mw.Lock("entity.consent.apply", "secret", entitymanager.ConsentPOSTHandler)).Methods(http.MethodPost)
	r.HandleFunc("/insight", mw.Lock("entity.user.view", "secret", entitymanager.InsightPOSTHandler)).Methods(http.MethodPost)

	return r
}

//GetSecureRoutes returns a router for the Security Server
func GetSecureRoutes() http.Handler {
	r := mux.NewRouter()

	store := fakes.NewFakeStore()
	securitymanager.InitializeManager(store)
	r.HandleFunc("/token", securitymanager.TokenPOSTHandler).Methods(http.MethodPost)

	mw := middle.NewResourceInspector(securitymanager.NewSecureAPIService())
	r.HandleFunc("/query/{client:[a-z]+}", mw.Lock("kong.client.query", "secret", securitymanager.ConsentQueryHandler)).Methods(http.MethodGet)

	r.HandleFunc("/inspect", securitymanager.ResourceInfoHandler).Methods(http.MethodPost)
	r.HandleFunc("/info", securitymanager.ClientInfoHandler).Methods(http.MethodPost)

	return r
}

//GetViewrRoutes returns a router for the Sample UI
func GetViewrRoutes(name, secret string, clnt *http.Client, securityUrl, entityUrl, authorityUrl string) http.Handler {
	r := mux.NewRouter()

	svc := stores.NewApplicationService(name, secret, clnt, securityUrl, entityUrl, authorityUrl)
	mw := middle.NewClientMiddleware(svc)
	r.HandleFunc("/", mw.Intent(viewr.HandleIndexGET, map[string]bool{"api.user.view": true})).Methods(http.MethodGet)
	r.HandleFunc("/callback", mw.Callback).Queries("ut", "{ut:[a-zA-Z0-9]+}", "redirect", "{redirect}").Methods(http.MethodGet)

	return r
}

//GetApiRoutes returns a router for the Sample Resource
func GetApiRoutes(clnt *http.Client, securityUrl, entityUrl string) http.Handler {
	r := mux.NewRouter()

	svc := stores.NewAPIService(clnt, securityUrl, entityUrl)
	mw := middle.NewResourceInspector(svc)

	r.HandleFunc("/profile", mw.Lock("api.profile.view", "secret", api.HandleProfileGET)).Methods(http.MethodGet)
	r.HandleFunc("/user", mw.Lock("api.user.view", "secret", api.HandleUserGET)).Methods(http.MethodGet)

	return r
}
