package samples

import (
	"log"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/louisevanderlith/kong"
	"github.com/louisevanderlith/kong/samples/controllers"
)

func TestResource_Middleware_SetContext(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/profile", nil)

	token := "JBvuOLviaslia2pU2kHrcmCcSSUlrcl8dehYk3QvF7PSl1YpeY7Lice62zIDyhhcU0Iw+5x7aQCN/RC/Q4HWNooqe2AqSIzihv3UixUFW5XIA99bDpvleLvDL0/33zKDZzMTA+ihs/9SHAIwlCgBRrnY/DT8HLrFUftQGMZyQUUeBkSqjsntcRwIQ82iy3uZ68dc5tafO36NHdu7SJxwmIAGmjWZ3fPb6+Auk/4l1gvNYreeuITmYawUovQHJjhU7+eKY4OKJILINxCDFpT2W+hS4PFYDoQYgD762DPxA2sU80idpl9n2WmGVwvzGxfYPcvcbbJj10UaDIAHywEC"
	req.Header.Set("Authorization", "Bearer "+token)
	// add Bearer header
	rr := httptest.NewRecorder()

	handle := kong.ResourceMiddleware("api.profile.view", "secret", "https://localhost:000", controllers.HandleProfileGET)
	handle(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatal(rr.Code, rr.Body.String())
	}

	log.Println(rr.Body.String())
}
