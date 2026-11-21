package pcaecho

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/labstack/echo/v4"

	pca "github.com/Atlas-Authorization/pca-go"
)

// echoHarness runs the shared adapter acceptance matrix through the Echo middleware.
func echoHarness(opts pca.RequirePCAOptions) func(pca.AcceptanceRequest) pca.AcceptanceObservation {
	var ran bool
	var authorized *pca.AuthorizedOperation
	e := echo.New()
	e.Use(RequirePCA(pca.WithAcceptanceOperation(opts)))
	e.POST("/*", func(c echo.Context) error {
		ran = true
		if res, ok := Authorization(c); ok {
			authorized = res.Operation
		}
		return c.NoContent(http.StatusOK)
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
		e.ServeHTTP(w, hr)
		return pca.AcceptanceObservation{Status: w.Code, HandlerRan: ran, Operation: authorized}
	}
}

func TestEchoAdapterAcceptance(t *testing.T) {
	got, err := pca.RunAdapterAcceptance(echoHarness)
	if err != nil {
		t.Fatal(err)
	}
	if bad := pca.AcceptanceDiff(got); len(bad) > 0 {
		t.Fatalf("scenarios that differ from the expected matrix: %v (got %v)", bad, got)
	}
}
