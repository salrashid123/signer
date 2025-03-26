module main

go 1.24.0

require (
	github.com/google/go-tpm v0.9.1
	github.com/google/go-tpm-tools v0.4.4
	github.com/salrashid123/signer v0.0.0
)

require (
	github.com/google/go-configfs-tsm v0.2.2 // indirect
	golang.org/x/sys v0.21.0 // indirect
)

replace github.com/salrashid123/signer => ../
