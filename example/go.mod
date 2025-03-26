module main

go 1.24.0

require (
	github.com/foxboron/go-tpm-keyfiles v0.0.0-20241207144721-04534a2f2feb
	github.com/google/go-tpm v0.9.1
	github.com/google/go-tpm-tools v0.4.4
	github.com/salrashid123/signer v0.0.0
)

require (
	github.com/golang/protobuf v1.5.4 // indirect
	github.com/google/uuid v1.6.0 // indirect
	golang.org/x/crypto v0.24.0 // indirect
	golang.org/x/sys v0.21.0 // indirect
	google.golang.org/protobuf v1.34.1 // indirect
)

replace github.com/salrashid123/signer => ../
