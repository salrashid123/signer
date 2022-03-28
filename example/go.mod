module main

go 1.17

require (
	github.com/salrashid123/signer/kms v0.0.0
	github.com/salrashid123/signer/pem v0.0.0
	github.com/salrashid123/signer/tpm v0.0.0
	// github.com/salrashid123/signer/kms v0.0.0
	// github.com/salrashid123/signer/pem v0.0.0
	golang.org/x/net v0.0.0-20211015210444-4f30a5c0130f // indirect
)

require (
	cloud.google.com/go v0.94.1 // indirect
	cloud.google.com/go/kms v1.0.0 // indirect
	github.com/golang/groupcache v0.0.0-20200121045136-8c9f03a8e57e // indirect
	github.com/golang/protobuf v1.5.2 // indirect
	github.com/google/go-cmp v0.5.6 // indirect
	github.com/google/go-tpm v0.3.3 // indirect
	github.com/google/go-tpm-tools v0.3.0 // indirect
	github.com/googleapis/gax-go/v2 v2.1.0 // indirect
	go.opencensus.io v0.23.0 // indirect
	golang.org/x/oauth2 v0.0.0-20210819190943-2bc19b11175f // indirect
	golang.org/x/sys v0.0.0-20210908233432-aa78b53d3365 // indirect
	golang.org/x/text v0.3.6 // indirect
	google.golang.org/api v0.57.0 // indirect
	google.golang.org/appengine v1.6.7 // indirect
	google.golang.org/genproto v0.0.0-20211016002631-37fc39342514 // indirect
	google.golang.org/grpc v1.40.0 // indirect
	google.golang.org/protobuf v1.27.1 // indirect
)

replace (
	github.com/salrashid123/signer/kms => ../kms
	github.com/salrashid123/signer/pem => ../pem
	github.com/salrashid123/signer/tpm => ../tpm
)
