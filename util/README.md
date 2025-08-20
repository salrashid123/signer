### Create CSR and self-signed x509 Certificates using Signer

The following uses TPM based signers

#### Create Keys

```bash

### if using swtpm:
# rm -rf /tmp/myvtpm && mkdir /tmp/myvtpm
# sudo swtpm socket --tpmstate dir=/tmp/myvtpm --tpm2 --server type=tcp,port=2321 --ctrl type=tcp,port=2322 --flags not-need-init,startup-clear

# export TPM2TOOLS_TCTI="swtpm:port=2321"


 # using H2 template ( https://gist.github.com/salrashid123/9822b151ebb66f4083c5f71fd4cdbe40 )
printf '\x00\x00' > unique.dat
tpm2_createprimary -C o -G ecc  -g sha256 \
   -c primary.ctx -a "fixedtpm|fixedparent|sensitivedataorigin|userwithauth|noda|restricted|decrypt" -u unique.dat
 ### which you ca eventually export the keys to TSS
 ## tpm2tss-genkey -u key.pub -r key.priv private.pem

 # or 
 # tpm2_createprimary -C o -c primary.ctx


## ===== RSA
 tpm2_create -G rsa2048:rsassa:null -g sha256 -u key.pub -r key.priv -C primary.ctx
 tpm2_flushcontext -t
 tpm2_load -C primary.ctx -u key.pub -r key.priv -c key.ctx
 tpm2_evictcontrol -C o -c key.ctx 0x81008001
 tpm2_flushcontext -t
 tpm2_encodeobject -C primary.ctx -u key.pub -r key.priv -o private.pem

## ===== ECC
 tpm2_create -G ecc:ecdsa  -g sha256  -u key.pub -r key.priv -C primary.ctx
 tpm2_flushcontext -t
 tpm2_load -C primary.ctx -u key.pub -r key.priv -c key.ctx
 tpm2_evictcontrol -C o -c key.ctx 0x81008002
 tpm2_flushcontext -t 
 tpm2_encodeobject -C primary.ctx -u key.pub -r key.priv -o private.pem
```

#### Create CSR 

```bash
go run csrgen/csrgen.go --filename /tmp/server.csr --sni server.domain.com \
   --persistentHandle=0x81008001 --useECCRawFormat=false --tpm-path="127.0.0.1:2321"
```

#### Create self-signed cert with TPM based key

```bash
## for RSA keys
go run  certgen/certgen.go  --filename /tmp/server.crt \
   --persistentHandle=0x81008001 --sni server.domain.com --cn=server.domain.com  \
    --tpm-path="127.0.0.1:2321"

## for ECC keys
go run  certgen/certgen.go  --filename /tmp/server.crt \
   --persistentHandle=0x81008002 --sni server.domain.com \
   --cn=server.domain.com --useECCRawFormat=false --tpm-path="127.0.0.1:2321"
```

