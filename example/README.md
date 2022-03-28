



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

example usage of TPM2_TOOLS to import an external RSA key and seal it to handle

```
# tpm2_createprimary -Grsa2048:aes128cfb -C o -c parent.ctx

# tpm2_import -C parent.ctx -G rsa -i user10_rsa.key -u key.pub -r key.priv

# tpm2_load  -C parent.ctx -u key.pub -r key.priv -c key.ctx

# tpm2_evictcontrol -C o -c key.ctx 0x81010002
persistent-handle: 0x81010002
action: persisted

```