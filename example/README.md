



### KMS

Create keys

```bash
gcloud kms keyrings create kr  --location=us-central1

gcloud kms keys create s --keyring=kr --purpose=asymmetric-signing --location=us-central1 --default-algorithm=rsa-sign-pkcs1-2048-sha256
```


### TPM


example usage of TPM2_TOOLS to import an external RSA key and seal it to handle

```bash
tpm2_createprimary -C o -c primary.ctx

tpm2_import -C primary.ctx -G rsa -i user10.key -u key.pub -r key.priv
tpm2_load  -C primary.ctx -u key.pub -r key.priv -c key.ctx
tpm2_evictcontrol -C o -c  0x81010002
tpm2_evictcontrol -C o -c key.ctx 0x81010002
```