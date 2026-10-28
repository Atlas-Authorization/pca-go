module example.com/pca-gin-server

go 1.25.0

require (
	github.com/Atlas-Authorization/pca-go v0.0.0
	github.com/gin-gonic/gin v1.10.0
)

replace github.com/Atlas-Authorization/pca-go => ../..
