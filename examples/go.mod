module github.com/InsideOutSec/goproxy/examples/goproxy-transparent

go 1.20

require (
	github.com/coder/websocket v1.8.12
	github.com/InsideOutSec/goproxy v1.5.0
	github.com/InsideOutSec/goproxy/ext v0.0.0-20250117123040-e9229c451ab8
	github.com/inconshreveable/go-vhost v1.0.0
)

require (
	golang.org/x/net v0.34.0 // indirect
	golang.org/x/text v0.21.0 // indirect
)

replace github.com/InsideOutSec/goproxy => ../
