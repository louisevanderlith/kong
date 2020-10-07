package middle

import (
	"fmt"
	"github.com/louisevanderlith/droxolite/mix"
	"net/http"
	"strings"
)

func IdentityModifer(f mix.MixerFactory, r *http.Request) {
	claims := GetIdentity(r)
	f.SetValue("Identity", claims)

	if claims != nil {
		if !strings.Contains(f.GetTitle(), " - ") {
			profTitle := fmt.Sprintf("%s - %s", f.GetTitle(), claims.GetProfile())
			f.ChangeTitle(profTitle)
		}

		f.SetValue("Token", GetToken(r))

		//User Details
		if claims.HasUser() {
			//never display the user's key on the front-end
			f.SetValue("Username", GetUserIdentity(r).GetDisplayName())
		}
	}
}
