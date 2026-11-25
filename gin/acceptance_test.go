package pcagin

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"

	pca "github.com/Atlas-Authorization/pca-go"
)

// ginHarness runs the shared adapter acceptance matrix through the Gin middleware.
func ginHarness(opts pca.RequirePCAOptions) func(pca.AcceptanceRequest) pca.AcceptanceObservation {
	gin.SetMode(gin.TestMode)
	var ran bool
	var authorized *pca.AuthorizedOperation
	r := gin.New()
	r.Use(RequirePCA(pca.WithAcceptanceOperation(opts)))
	r.POST("/*any", func(c *gin.Context) {
		ran = true
		if res, ok := Authorization(c); ok {
			authorized = res.Operation
		}
		c.Status(http.StatusOK)
	})
	return func(req pca.AcceptanceRequest) pca.AcceptanceObservation {
		ran, authorized = false, nil
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
		return pca.AcceptanceObservation{Status: w.Code, HandlerRan: ran, Operation: authorized}
	}
}

func TestGinAdapterAcceptance(t *testing.T) {
	got, err := pca.RunAdapterAcceptance(ginHarness)
	if err != nil {
		t.Fatal(err)
	}
	if bad := pca.AcceptanceDiff(got); len(bad) > 0 {
		t.Fatalf("scenarios that differ from the expected matrix: %v (got %v)", bad, got)
	}
}
