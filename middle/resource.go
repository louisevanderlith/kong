package middle

import (
	"context"
	"log"
	"net/http"
)

type ResourceInspector struct {
	clnt        *http.Client
	securityUrl string
	managerUrl  string
}

func NewResourceInspector(clnt *http.Client, securityUrl, managerUrl string) ResourceInspector {
	return ResourceInspector{
		clnt:        clnt,
		securityUrl: securityUrl,
		managerUrl:  managerUrl,
	}
}

//ResourceMiddleware
func (ins ResourceInspector) Middleware(scope, secret string, handle http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		token, err := GetBearerToken(r)

		if err != nil {
			log.Println("Get Bearer Token Error", err)
			http.Error(w, "", http.StatusUnauthorized)
			return
		}

		claims, err := FetchIdentity(ins.clnt, []byte(token), ins.securityUrl+"/inspect", scope, secret)

		if err != nil {
			log.Println("Exchange Error", err)
			http.Error(w, "", http.StatusUnauthorized)
			return
		}

		idn := context.WithValue(r.Context(), "claims", claims)
		r = r.WithContext(idn)

		if claims.HasUser() && len(ins.managerUrl) > 0 {
			usrclaims, err := FetchUserIdentity(ins.clnt, []byte(claims.GetUserToken()), []byte(token), ins.managerUrl)

			if err != nil {
				log.Println("User Exchange Error", err)
				http.Error(w, "", http.StatusUnauthorized)
			}

			idn := context.WithValue(r.Context(), "userclaims", usrclaims)
			r = r.WithContext(idn)
		}

		handle(w, r)
	}
}
