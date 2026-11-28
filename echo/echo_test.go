package pcaecho

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/labstack/echo/v4"

	pca "github.com/Atlas-Authorization/pca-go"
)

// A request with no proof is refused by the guard and never reaches the handler.
func TestRefusesWithoutProof(t *testing.T) {
	ran := false
	e := echo.New()
	e.Use(RequirePCA(pca.RequirePCAOptions{SignatureOnly: true, Audience: "https://api.example"}))
	e.GET("/x", func(c echo.Context) error { ran = true; return c.String(200, "ok") })
	w := httptest.NewRecorder()
	e.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/x", nil))
	if ran || w.Code < 400 {
		t.Fatalf("handler ran=%v status=%d, want a refusal before the handler", ran, w.Code)
	}
}
