// Package pcaecho adapts the pca net/http guard to Echo: RequirePCA is the same fail-closed guard (every refusal is written by
// the core middleware; the handler chain runs only on an allow).
package pcaecho

import (
	"net/http"

	"github.com/labstack/echo/v4"

	pca "github.com/Atlas-Authorization/pca-go"
)

// RequirePCA returns Echo middleware running pca.RequirePCA. On a refusal the response is already written and the next handler
// is not called; on an allow the request (with the verdict in its context) reaches it, and its error is returned unchanged.
func RequirePCA(opts pca.RequirePCAOptions) echo.MiddlewareFunc {
	guard := pca.RequirePCA(opts)
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			var herr error
			guard(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
				c.SetRequest(r)
				herr = next(c)
			})).ServeHTTP(c.Response(), c.Request())
			return herr
		}
	}
}

// Verdict returns the verified verdict and PCActn the guard stored for this request (ok is false when it did not run).
func Verdict(c echo.Context) (*pca.Verdict, map[string]any, bool) {
	return pca.FromContext(c.Request().Context())
}

// Authorization returns the authorize-mode result the guard stored for this request.
func Authorization(c echo.Context) (*pca.AuthorizeResult, bool) {
	return pca.AuthorizationFromContext(c.Request().Context())
}
