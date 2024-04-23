



### KMS

Create keys

```bash
gcloud kms keyrings create kr  --location=us-central1

## rsa-sign-pkcs1-2048-sha256
gcloud kms keys create rskey1 --keyring=kr --purpose=asymmetric-signing --location=us-central1 --default-algorithm=rsa-sign-pkcs1-2048-sha256

## rsa-sign-pss-2048-sha256
gcloud kms keys create rskey2 --keyring=kr --purpose=asymmetric-signing --location=us-central1 --default-algorithm=rsa-sign-pss-2048-sha256

## ec-sign-p256-sha256
gcloud kms keys create ec1 --keyring=kr --purpose=asymmetric-signing --location=us-central1 --default-algorithm=ec-sign-p256-sha256
```


### TPM


example usage generates a new TPM unrestricted RSA key and sign,verify some data.


You can create the persistent handles using go-tpm or using  `tpm2_tools` and make it persistent, 

```bash
cd example/

## for rsapersistentHandle

 tpm2_createprimary -C e -c primary.ctx
 tpm2_create -G rsa2048:rsassa:null -g sha256 -u key.pub -r key.priv -C primary.ctx
 tpm2_load -C primary.ctx -u key.pub -r key.priv -c key.ctx
 tpm2_evictcontrol -C o -c key.ctx 0x81008001

## for eccpersistentHandle

 tpm2_createprimary -C e -c primary.ctx
 tpm2_create -G ecc:ecdsa  -g sha256  -u key.pub -r key.priv -C primary.ctx
 tpm2_load -C primary.ctx -u key.pub -r key.priv -c key.ctx
 tpm2_evictcontrol -C o -c key.ctx 0x81008002


## for policyRSApersistentHandle

 tpm2_startauthsession -S session.dat
 tpm2_policypcr -S session.dat -l sha256:23  -L policy.dat
 tpm2_flushcontext session.dat
 tpm2_createprimary -C o -c primary2.ctx
 tpm2_create -G rsa2048:rsassa:null -g sha256 -u rsa2.pub -r rsa2.priv -C primary2.ctx  -L policy.dat
 tpm2_load -C primary2.ctx -u rsa2.pub -r rsa2.priv -c rsa2.ctx
 tpm2_evictcontrol -C o -c rsa2.ctx 0x81008004

## ===== 

cd example

## RSA
go run sign_verify_tpm/rsa/main.go --handle=0x81008001

## ECC
go run sign_verify_tpm/ecc/main.go --handle=0x81008002 

## RSA with policy
go run sign_verify_tpm/policy/main.go --handle=0x81008004

```


