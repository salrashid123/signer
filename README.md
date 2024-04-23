#### crypto.Signer, implementations for Google Cloud KMS and Trusted Platform Modules

where private keys as embedded inside:

* Google Cloud KMS 
* Trusted Platform Module (TPM)

Basically, you will get a `crypto.Signer` interface where the private keys are saved on those platform.  

Use the signer to create a TLS session, sign CA/CSRs, generate signed url or just sign anything.

Some implementations:

- `kms/`:  Sample that implements `crypto.Signer` using Google Cloud KMS.
- `tpm/`:  Sample that implements `crypto.Signer`  using `go-tpm` library for Trusted Platform Module    This internally uses [go-tpm-tools.client.GetSigner()](https://pkg.go.dev/github.com/google/go-tpm-tools/client#Key.GetSigner)

- `util/certgen/`:  Library that generates a self-signed x509 certificate for the KMS and TPM based signers above
- `util/csrgen/`:  Library that generates a CSR using the key in KMS or TPM 


see the [example/](example/) folder for more information.

### Usage Signer

Initialize a signer and directly use `.sign()` as shown in this sample for GCS SignedURL:

- [GCS SignedURL for KMS](https://github.com/salrashid123/kms_service_accounts/blob/master/main.go#L56)
* [GCS signedURLs and GCP Authentication with Trusted Platform Module](https://github.com/salrashid123/gcs_tpm)

### TPM Signer Device management

For TPM Signer, there are two modes of operation:

* managed externally

  The TPM device is managed externally outside of the signer.  You have to instantiate the TPM device ReadWriteCloser and client.Key outside of the library and pass that in.

  The advantage of this is you control it opening and closing.  You must close the key and closer before calling another signing operation

* managed by library

  This is the preferred mode: you just pass the uint32 handle for the key and the path to the tpm device as string and the library opens/closes it as needed.

  If the device is busy or the TPM is in use during invocation, the operation will fail.
  
TODO use a backoff retry similar to [tpmrand](https://github.com/salrashid123/tpmrand) to prevent contention.

Please note that we are persisting the handle here for easy access.  The more formal way is to save the entire chain of keys (which is a TODO)

A limitation of using persistent handles is that its limited on a TPM (typically 7 slots).  You have to evict (i.,e delete) one before loading a new one.


If you just want to issue JWT's, see

* [https://github.com/salrashid123/golang-jwt-tpm](https://github.com/salrashid123/golang-jwt-tpm)
* [https://github.com/salrashid123/golang-jwt-pkcs11](https://github.com/salrashid123/golang-jwt-pkcs11)

### Usage TLS

see `example/mtls` folder

* for tpm see [mTLS with TPM bound private key](https://github.com/salrashid123/go_tpm_https_embed)
* for kms see [mTLS with Google Cloud KMS](https://github.com/salrashid123/kms_golang_signer)


### Sign/Verify PSS

see `example/sign_verify` folder

### Usage: Generate self-signed certificate

see `util/`

```bash
go run certgen/certgen.go -cn server.domain.com
```

### Usage: Generate CSR

see `util/csrgen/`

```bash
go run certgen/certgen.go -cn server.domain.com
```

