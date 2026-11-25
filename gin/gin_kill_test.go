package pcagin

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"

	pca "github.com/Atlas-Authorization/pca-go"
)

// An allowed request leaves the chain un-aborted and a refused one aborts it: an outer middleware observes IsAborted after the
// guard and the handlers have run. Runs through the shared acceptance matrix so both outcomes occur with real proofs.
func TestKillAbortStateMatchesTheVerdict(t *testing.T) {
	var allowedSeen, refusedSeen int
	factory := func(opts pca.RequirePCAOptions) func(pca.AcceptanceRequest) pca.AcceptanceObservation {
		gin.SetMode(gin.TestMode)
		var ran, aborted bool
		r := gin.New()
		r.Use(func(c *gin.Context) { c.Next(); aborted = c.IsAborted() })
		r.Use(RequirePCA(pca.WithAcceptanceOperation(opts)))
		r.POST("/*any", func(c *gin.Context) { ran = true; c.Status(http.StatusOK) })
		return func(req pca.AcceptanceRequest) pca.AcceptanceObservation {
			ran, aborted = false, false
			text, err := pca.Canonicalize(req.Body)
			if err != nil {
				return pca.AcceptanceObservation{Status: 400}
			}
			hr := httptest.NewRequest(http.MethodPost, req.Path, bytes.NewReader([]byte(text)))
			for k, v := range req.Headers {
				hr.Header.Set(k, v)
			}
			w := httptest.NewRecorder()
			r.ServeHTTP(w, hr)
			if ran {
				allowedSeen++
				if aborted || w.Code != http.StatusOK {
					t.Errorf("an allowed request must not be aborted (aborted=%v status=%d, %s)", aborted, w.Code, req.Path)
				}
			} else {
				refusedSeen++
				if !aborted || w.Code < 400 {
					t.Errorf("a refused request must abort the chain (aborted=%v status=%d, %s)", aborted, w.Code, req.Path)
				}
			}
			return pca.AcceptanceObservation{Status: w.Code, HandlerRan: ran}
		}
	}
	if _, err := pca.RunAdapterAcceptance(factory); err != nil {
		t.Fatal(err)
	}
	if allowedSeen == 0 || refusedSeen == 0 {
		t.Fatalf("the matrix must exercise both outcomes: allowed=%d refused=%d", allowedSeen, refusedSeen)
	}
}

// A refusal also stops later middleware, not just the handler.
func TestKillRefusalStopsLaterMiddleware(t *testing.T) {
	gin.SetMode(gin.TestMode)
	later := false
	r := gin.New()
	r.Use(RequirePCA(pca.RequirePCAOptions{SignatureOnly: true, Audience: "https://api.example"}))
	r.Use(func(c *gin.Context) { later = true; c.Next() })
	r.GET("/x", func(c *gin.Context) { c.String(200, "ok") })
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/x", nil))
	if later || w.Code < 400 {
		t.Fatalf("later middleware ran=%v status=%d, want a refusal that aborts the chain", later, w.Code)
	}
}
