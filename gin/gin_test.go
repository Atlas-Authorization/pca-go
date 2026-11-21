package pcagin

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"

	pca "github.com/Atlas-Authorization/pca-go"
)

// A request with no proof is refused by the guard and never reaches the handler.
func TestRefusesWithoutProof(t *testing.T) {
	gin.SetMode(gin.TestMode)
	ran := false
	r := gin.New()
	r.Use(RequirePCA(pca.RequirePCAOptions{SignatureOnly: true, Audience: "https://api.example"}))
	r.GET("/x", func(c *gin.Context) { ran = true; c.String(200, "ok") })
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/x", nil))
	if ran || w.Code < 400 {
		t.Fatalf("handler ran=%v status=%d, want a refusal before the handler", ran, w.Code)
	}
}
