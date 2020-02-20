module github.com/EquityZen/vault-k8s-utils

go 1.12

require (
	github.com/gin-gonic/gin v1.4.0
	github.com/go-resty/resty/v2 v2.1.0
	github.com/kr/pretty v0.1.0 // indirect
	github.com/phayes/freeport v0.0.0-20180830031419-95f893ade6f2
	github.com/spf13/cobra v0.0.5
	github.com/stretchr/testify v1.5.1
	golang.org/x/sys v0.0.0-20190523142557-0e01d883c5c5 // indirect
	gopkg.in/check.v1 v1.0.0-20180628173108-788fd7840127 // indirect
)

replace github.com/ugorji/go v1.1.4 => github.com/ugorji/go/codec v0.0.0-20190204201341-e444a5086c43
