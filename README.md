#### crypto.Signer, implementations for Google Cloud KMS and Trusted Platform Modules

where private keys as embedded inside:

* Google Cloud KMS 
* Trusted Platform Module (TPM)
* Hashicorp Vault

Basically, you will get a `crypto.Signer` interface where the private keys are saved on those platform.  

Use the signer to create a TLS session, sign CA/CSRs, generate signed url or just sign anything.

Some implementations:

- `kms/`:  Sample that implements `crypto.Signer` using Google Cloud KMS
- `tpm/`:  Sample that implements `crypto.Signer`  using `go-tpm` library for Trusted Platform Module
- `vault/`:  `crypto.Signer` for use with [Hashicorp Vault Transit Engine](https://www.vaultproject.io/docs/secrets/transit)
- `util/certgen/`:  Library that generates a self-signed x509 certificate for the KMS and TPM based signers above
- `util/csrgen/`:  Library that generates a CSR using the key in KMS or TPM 


see the [example/](example/) folder for more information.

### Usage Signer

Initialize a signer and directly use `.sign()` as shown in this sample for GCS SignedURL:

- [GCS SignedURL for KMS](https://github.com/salrashid123/kms_service_accounts/blob/master/main.go#L56)
* [GCS signedURLs and GCP Authentication with Trusted Platform Module](https://github.com/salrashid123/gcs_tpm)

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

