module main

go 1.22

toolchain go1.22.2

require (
	github.com/google/go-tpm v0.9.1-0.20240510201744-5c2f0887e003
	github.com/google/go-tpm-tools v0.4.4
	github.com/salrashid123/signer/tpm v0.0.0-00010101000000-000000000000
)

require (
	github.com/golang/protobuf v1.5.3 // indirect
	github.com/google/go-configfs-tsm v0.2.2 // indirect
	github.com/google/go-sev-guest v0.9.3 // indirect
	github.com/google/go-tdx-guest v0.3.1 // indirect
	github.com/google/logger v1.1.1 // indirect
	github.com/google/uuid v1.3.1 // indirect
	github.com/pborman/uuid v1.2.1 // indirect
	github.com/pkg/errors v0.9.1 // indirect
	go.uber.org/multierr v1.11.0 // indirect
	golang.org/x/crypto v0.17.0 // indirect
	golang.org/x/sys v0.15.0 // indirect
	google.golang.org/protobuf v1.31.0 // indirect
)

replace (
	github.com/salrashid123/signer/kms => ../kms
	github.com/salrashid123/signer/tpm => ../tpm
)
