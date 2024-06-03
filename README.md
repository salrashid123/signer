#### crypto.Signer, implementations for Google Cloud KMS and Trusted Platform Modules

where private keys as embedded inside:

* `Google Cloud KMS` 
* `Trusted Platform Module (TPM)`

Basically, you will get a `crypto.Signer` interface where the private keys are saved on those platform.  

Use the signer to create a TLS session, sign CA/CSRs, generate signed url or just sign anything.

Some implementations:

- `kms/`:  Sample that implements `crypto.Signer` using Google Cloud KMS.
- `tpm/`:  Sample that implements `crypto.Signer`  using `go-tpm` library for Trusted Platform Module    This internally uses [go-tpm-tools.client.GetSigner()](https://pkg.go.dev/github.com/google/go-tpm-tools/client#Key.GetSigner)

- `util/certgen/`:  Library that generates a self-signed x509 certificate for the KMS and TPM based signers above
- `util/csrgen/`:  Library that generates a CSR using the key in KMS or TPM 

see the [example/](example/) folder for more information.

---

>> **NOTE** there will be a breaking change if you are using this library for TPM based signature after `v0.8.0`.  The new structure uses the [tpm-direct](https://github.com/google/go-tpm/releases/tag/v0.9.0) API.  If you would rather use the tpm2/legacy branch, please use the signer at [v0.7.2](https://github.com/salrashid123/signer/releases/tag/v0.7.2).  This change also *removes* the library managed device.  The caller must provide a pre-authorized key (there was no way the library could authorize the variety of auth sessions...it must be provided in)


>> this library is not supported by google

---

### Usage Signer

Initialize a signer and directly use `.sign()` as shown in this sample for GCS SignedURL:

* [GCS SignedURL for KMS](https://github.com/salrashid123/kms_service_accounts)
* [GCS signedURLs and GCP Authentication with Trusted Platform Module](https://github.com/salrashid123/gcs_tpm)

### Usage TLS

* for tpm see [mTLS with TPM bound private key](https://github.com/salrashid123/go_tpm_https_embed)
* for kms see [mTLS with Google Cloud KMS](https://github.com/salrashid123/kms_golang_signer)

### Sign/Verify PSS

see `example/sign_verify*` folders

### Sign/Verify ECC

The default output signature format for ECC based keys is ASN1 format as described in [ecdsa.SignASN1](https://pkg.go.dev/crypto/ecdsa#Sign)

If you need the raw output format, set `ECCRawOutput:       true` in the config.

See the examples folder for usage

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

---


If you just want to issue JWT's, see

* [https://github.com/salrashid123/golang-jwt-tpm](https://github.com/salrashid123/golang-jwt-tpm)
* [https://github.com/salrashid123/golang-jwt-pkcs11](https://github.com/salrashid123/golang-jwt-pkcs11)
