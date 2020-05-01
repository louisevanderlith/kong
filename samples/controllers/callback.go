package controllers

import (
	"testing"
)

func HandleCallbackGET(t *testing.T) {
	/*c.Request.ParseForm()
	state := c.Query("state")

	session := sessions.Default(c)

	cstate := session.Get("state")

	if state != cstate {
		c.AbortWithError(http.StatusBadRequest, errors.New("state invalid"))
		return
	}

	code := c.Query("code")
	if code == "" {
		c.AbortWithError(http.StatusBadRequest, errors.New("code not found"))
		return
	}

	token, err := cfg.Exchange(context.Background(), code)

	if err != nil {
		c.AbortWithError(http.StatusInternalServerError, err)
		return
	}

	jsTokn, err := json.Marshal(token)

	if err != nil {
		c.AbortWithError(http.StatusInternalServerError, err)
		return
	}

	session.Set("full_token", jsTokn)
	session.Set("access_token", token.AccessToken)

	err = session.Save()

	if err != nil {
		c.AbortWithError(http.StatusInternalServerError, err)
		return
	}

	c.Redirect(http.StatusSeeOther, "/")*/
}
