



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

First install latest `tpm2_tools`

```bash
## install latest tpm2-tools:
####  https://github.com/salrashid123/tpm2/tree/master?tab=readme-ov-file#installing-tpm2_tools-golang
#### https://tpm2-tools.readthedocs.io/en/latest/INSTALL/
```

```bash
cd example/

## if you want to use a software TPM, 
# rm -rf /tmp/myvtpm && mkdir /tmp/myvtpm
# sudo swtpm socket --tpmstate dir=/tmp/myvtpm --tpm2 --server type=tcp,port=2321 --ctrl type=tcp,port=2322 --flags not-need-init,startup-clear

## then specify "127.0.0.1:2321"  as the TPM device path in the examples
## then for tpm2_tools, export the following var
# export TPM2TOOLS_TCTI="swtpm:port=2321"

## note if you want, the primary can be the "H2" profile from https://www.hansenpartnership.com/draft-bottomley-tpm2-keys.html#name-parent
## see https://gist.github.com/salrashid123/9822b151ebb66f4083c5f71fd4cdbe40
# printf '\x00\x00' > unique.dat
# tpm2_createprimary -C o -G ecc  -g sha256  -c primary.ctx -a "fixedtpm|fixedparent|sensitivedataorigin|userwithauth|noda|restricted|decrypt" -u unique.dat


## RSA - no password
	tpm2_createprimary -C o -G rsa2048:aes128cfb -g sha256 -c primary.ctx -a 'restricted|decrypt|fixedtpm|fixedparent|sensitivedataorigin|userwithauth|noda'
	tpm2_create -G rsa2048:rsassa:null -g sha256 -u key.pub -r key.priv -C primary.ctx
	tpm2_flushcontext  -t
	tpm2_getcap  handles-transient
	tpm2_load -C primary.ctx -u key.pub -r key.priv -c key.ctx
	tpm2_evictcontrol -C o -c key.ctx 0x81008001
	tpm2_flushcontext  -t

## rsa-pss
	tpm2_createprimary -C o -G rsa2048:aes128cfb -g sha256 -c primary.ctx -a 'restricted|decrypt|fixedtpm|fixedparent|sensitivedataorigin|userwithauth|noda'
	tpm2_create -G rsa2048:rsapss:null -g sha256 -u key.pub -r key.priv -C primary.ctx  --format=pem --output=rsapss_public.pem
	tpm2_flushcontext  -t
	tpm2_getcap  handles-transient 
	tpm2_load -C primary.ctx -u key.pub -r key.priv -c key.ctx
	tpm2_evictcontrol -C o -c key.ctx 0x81008004
	tpm2_flushcontext  -t

## ecc
	tpm2_createprimary -C o -G rsa2048:aes128cfb -g sha256 -c primary.ctx -a 'restricted|decrypt|fixedtpm|fixedparent|sensitivedataorigin|userwithauth|noda'
	tpm2_create -G ecc:ecdsa  -g sha256  -u key.pub -r key.priv -C primary.ctx  --format=pem --output=ecc_public.pem
	tpm2_flushcontext  -t
	tpm2_getcap  handles-transient  
	tpm2_load -C primary.ctx -u key.pub -r key.priv -c key.ctx
	tpm2_evictcontrol -C o -c key.ctx 0x81008005    
	tpm2_flushcontext  -t


## for policyRSApersistentHandle

	tpm2_pcrread sha256:23
	tpm2_startauthsession -S session.dat
	tpm2_policypcr -S session.dat -l sha256:23  -L policy.dat
	tpm2_flushcontext session.dat
	tpm2_flushcontext  -t
	tpm2_createprimary -C o -G rsa2048:aes128cfb -g sha256  -c primary.ctx -a 'restricted|decrypt|fixedtpm|fixedparent|sensitivedataorigin|userwithauth|noda'
	tpm2_create -G rsa2048:rsassa:null -g sha256 -u key.pub -r key.priv -C primary.ctx  -L policy.dat
	tpm2_flushcontext  -t
	tpm2_getcap  handles-transient
	tpm2_load -C primary.ctx -u key.pub -r key.priv -c key.ctx
	tpm2_evictcontrol -C o -c key.ctx 0x81008006
	tpm2_flushcontext  -t

## ===== 

cd example/

## RSA-SSA managed externally
go run sign_verify_tpm/rsassa/main.go --handle=0x81008001 --tpm-path="127.0.0.1:2321"

## RSA-PSS
go run sign_verify_tpm/rsapss/main.go --handle=0x81008004 --tpm-path="127.0.0.1:2321"

## ECC
go run sign_verify_tpm/ecc/main.go --handle=0x81008005 --tpm-path="127.0.0.1:2321"

## RSA with policy
go run sign_verify_tpm/policy/main.go --handle=0x81008006 --tpm-path="127.0.0.1:2321"
```

---

