module github.com/tdpn/tdpn-chain

go 1.22.2

require (
	github.com/tdpn/tdpn-chain/proto/gen/go v0.0.0
	google.golang.org/grpc v1.65.0
)

require (
	golang.org/x/net v0.25.0 // indirect
	golang.org/x/sys v0.20.0 // indirect
	golang.org/x/text v0.15.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20240528184218-531527333157 // indirect
	google.golang.org/protobuf v1.36.6 // indirect
)

replace github.com/tdpn/tdpn-chain/proto/gen/go => ./proto/gen/go
