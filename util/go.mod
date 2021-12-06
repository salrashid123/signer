module main

go 1.17

require (
	github.com/google/go-tpm v0.3.2
	github.com/google/go-tpm-tools v0.3.1
	github.com/salrashid123/signer/pem v0.0.0-00010101000000-000000000000
)

require (
	github.com/google/go-cmp v0.5.6 // indirect
	golang.org/x/sys v0.0.0-20210908233432-aa78b53d3365 // indirect
	google.golang.org/protobuf v1.27.1 // indirect
)

replace (
	github.com/salrashid123/signer/kms => ../kms
	github.com/salrashid123/signer/pem => ../pem
)
