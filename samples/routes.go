package samples

import (
	"github.com/gorilla/mux"
	"github.com/louisevanderlith/kong"
	"github.com/louisevanderlith/kong/samples/controllers"
	"net/http"
)

func GetAuthRoutes() http.Handler {
	r := mux.NewRouter()
	//Auth
	r.HandleFunc("/token", controllers.HandleTokenPOST).Methods(http.MethodPost)
	r.HandleFunc("/login", controllers.HandleLoginPOST).Methods(http.MethodPost)
	r.HandleFunc("/login", controllers.HandleLoginGET).Methods(http.MethodGet)
	r.HandleFunc("/consent", controllers.HandleConsentPOST).Methods(http.MethodPost)
	r.HandleFunc("/consent", controllers.HandleConsentGET).Methods(http.MethodGet)
	r.HandleFunc("/inspect", controllers.HandleInspectPOST).Methods(http.MethodPost)
	r.HandleFunc("/info", controllers.HandleInfoPOST).Methods(http.MethodPost)

	return r
}

func GetRoutes(clnt *http.Client, authUrl string) http.Handler {
	r := mux.NewRouter()
	//APP
	appMdl := kong.ClientMiddleware(clnt, "client.viewr", "secret", authUrl, controllers.HandleIndexGET)
	r.HandleFunc("/", appMdl).Methods(http.MethodGet)
	//r.HandleFunc("/callback", controllers.HandleCallbackGET).Methods(http.MethodGet)

	//API
	profMdl := kong.ResourceMiddleware("api.profile.view", "secret", authUrl, controllers.HandleProfileGET)
	r.HandleFunc("/profile", profMdl).Methods(http.MethodGet)
	usrMdl := kong.ResourceMiddleware("api.user.view", "secret", authUrl, controllers.HandleUserGET)
	r.HandleFunc("/user", usrMdl).Methods(http.MethodGet)

	return r
}
