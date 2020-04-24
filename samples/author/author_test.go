package author_test

import (
	"bytes"
	"encoding/json"
	"kong"
	"kong/samples/author/controllers"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestHandleTokenPOST(t *testing.T) {
	accs := kong.UserToken{}
	obj, err := json.Marshal(accs)

	if err != nil {
		t.Error(err)
		return
	}

	req := httptest.NewRequest(http.MethodPost, "/token", bytes.NewBuffer(obj))
	rr := httptest.NewRecorder()
	controllers.HandleTokenPOST(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatal(rr.Code, rr.Body.String())
	}
}
