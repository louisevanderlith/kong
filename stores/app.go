package stores

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"github.com/louisevanderlith/kong/prime"
	"github.com/louisevanderlith/kong/tokens"
	"net/http"
	"time"
)

type APPService interface {
	RequestToken(tokenreq prime.TokenRequest) (prime.TokenResponse, error)
	SendToConsent(w http.ResponseWriter, r *http.Request, exp time.Time)
	FetchIdentity(token []byte) (tokens.Identity, error)
	FetchUserIdentity(token []byte) (tokens.UserIdentity, error)
}

func NewApplicationService(name, secret string, client *http.Client, securityUrl, entityUrl, authorityUrl string) APPService {
	return appsvc{
		name:         name,
		secret:       secret,
		client:       client,
		securityUrl:  securityUrl,
		entityUrl:    entityUrl,
		authorityUrl: authorityUrl,
	}
}

type appsvc struct {
	client       *http.Client
	name         string
	secret       string
	securityUrl  string
	entityUrl    string
	authorityUrl string
}

func (a appsvc) RequestToken(tokenreq prime.TokenRequest) (prime.TokenResponse, error) {
	return sendForToken(a.client, a.name, a.secret, a.securityUrl, tokenreq)
}

func (a appsvc) SendToConsent(w http.ResponseWriter, r *http.Request, exp time.Time) {
	state := generateStateOauthCookie(w, exp)
	consntUrl := fmt.Sprintf("%s/consent?state=%s&client=%s&callback=%s", a.authorityUrl, state, a.name, r.RequestURI)
	http.Redirect(w, r, consntUrl, http.StatusTemporaryRedirect)
}

func (a appsvc) FetchIdentity(token []byte) (tokens.Identity, error) {
	return decodeIdentity(a.client, a.securityUrl+"/info", a.name, a.secret, token)
}

func (a appsvc) FetchUserIdentity(token []byte) (tokens.UserIdentity, error) {
	return decodeUserIdentity(a.client, a.entityUrl, token)
}

func generateStateOauthCookie(w http.ResponseWriter, expiration time.Time) string {
	b := make([]byte, 16)
	rand.Read(b)
	state := base64.URLEncoding.EncodeToString(b)
	cookie := http.Cookie{Name: "state", Value: state, Expires: expiration}
	http.SetCookie(w, &cookie)

	return state
}
