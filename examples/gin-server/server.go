package main

import (
	"errors"
	"net/http"

	pca "github.com/Atlas-Authorization/pca-go"
	"github.com/gin-gonic/gin"
)

// operationFor maps the request to the operation the handler will run. It is built from this route and the request body,
// never from the proof: the proof must have been signed for exactly this verb, resource and params.
func operationFor(r *http.Request, body []byte) (*pca.Operation, error) {
	v, err := pca.StrictParse(string(body))
	params, ok := v.(map[string]any)
	if err != nil || !ok {
		return nil, errors.New("body must be a JSON object")
	}
	return &pca.Operation{Verb: "payments.send", Resource: "payments/acme", Params: params}, nil
}

// ginPCA adapts the net/http middleware to Gin. A refusal is written by the middleware itself (401/403 JSON with a
// `doc` link); the handler chain is aborted so nothing runs.
func ginPCA(mw func(http.Handler) http.Handler) gin.HandlerFunc {
	return func(c *gin.Context) {
		passed := false
		mw(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
			passed = true
			c.Request = r // carries the verified proof in its context and the restored body
		})).ServeHTTP(c.Writer, c.Request)
		if !passed {
			c.Abort()
		}
	}
}

func newRouter(p *pca.Protected) *gin.Engine {
	r := gin.New()
	r.POST("/refunds", ginPCA(p.Middleware()), func(c *gin.Context) {
		az, _ := pca.AuthorizationFromContext(c.Request.Context())
		c.JSON(http.StatusOK, gin.H{"status": "done", "operation_id": az.Operation.ID})
	})
	return r
}
