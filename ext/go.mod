module github.com/InsideOutSec/goproxy/ext

go 1.20

require (
	github.com/InsideOutSec/goproxy v0.0.0-20250130185250-165e02b405b0
	github.com/stretchr/testify v1.10.0
	github.com/vadimi/go-http-ntlm/v2 v2.5.0
	golang.org/x/net v0.34.0
	golang.org/x/text v0.21.0
)

require (
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	github.com/vadimi/go-ntlm v1.2.1 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)

replace github.com/elazarl/goproxy v1.7.0 => github.com/InsideOutSec/goproxy v0.0.0-20250130183606-3aa294ee0ddc
