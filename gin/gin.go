// Package pcagin adapts the pca net/http guard to Gin: RequirePCA is the same fail-closed guard (every refusal is written by
// the core middleware; the handler chain runs only on an allow).
package pcagin

import (
	"net/http"

	"github.com/gin-gonic/gin"

	pca "github.com/Atlas-Authorization/pca-go"
)

// RequirePCA returns Gin middleware running pca.RequirePCA. On a refusal the response is already written and the chain is
// aborted; on an allow the request (with the verdict in its context) reaches the rest of the chain.
func RequirePCA(opts pca.RequirePCAOptions) gin.HandlerFunc {
	guard := pca.RequirePCA(opts) // built once: a bad configuration panics at construction, not per request
	return func(c *gin.Context) {
		allowed := false
		guard(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
			allowed = true
			c.Request = r // the guard may have replaced the context and the (re-buffered) body
			c.Next()
		})).ServeHTTP(c.Writer, c.Request)
		if !allowed {
			c.Abort()
		}
	}
}

// Verdict returns the verified verdict and PCActn the guard stored for this request (ok is false when it did not run).
func Verdict(c *gin.Context) (*pca.Verdict, map[string]any, bool) {
	return pca.FromContext(c.Request.Context())
}

// Authorization returns the authorize-mode result the guard stored for this request.
func Authorization(c *gin.Context) (*pca.AuthorizeResult, bool) {
	return pca.AuthorizationFromContext(c.Request.Context())
}
