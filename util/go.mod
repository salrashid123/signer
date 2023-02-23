module main

go 1.19

require (
	github.com/google/go-tpm v0.3.3
	github.com/google/go-tpm-tools v0.3.7
	github.com/salrashid123/signer/pem v0.0.0
)

require (
	golang.org/x/sys v0.0.0-20220722155257-8c9f86f7a55f // indirect
	google.golang.org/protobuf v1.27.1 // indirect
)

replace (
	github.com/salrashid123/signer/kms => ../kms
	github.com/salrashid123/signer/pem => ../pem
	github.com/salrashid123/signer/tpm => ../tpm
	github.com/salrashid123/signer/vault => ../vault
)
