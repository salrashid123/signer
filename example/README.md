



### KMS

Create keys

```bash
gcloud kms keyrings create kr  --location=us-central1

gcloud kms keys create s --keyring=kr --purpose=asymmetric-signing --location=us-central1 --default-algorithm=rsa-sign-pkcs1-2048-sha256
```


### TPM

```bash
# first generate tpm key

cd util
go run gen_tpm_cert/main.go
```

