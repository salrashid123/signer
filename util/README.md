### Create CSR and self-signed x509 Certificates using Signer

The following uses TPM based signers

#### Create Keys

```bash
## ===== RSA
 tpm2_createprimary -C e -c primary.ctx
 tpm2_create -G rsa2048:rsassa:null -g sha256 -u key.pub -r key.priv -C primary.ctx
 tpm2_load -C primary.ctx -u key.pub -r key.priv -c key.ctx
 tpm2_evictcontrol -C o -c key.ctx 0x81008001
## ===== ECC

 tpm2_createprimary -C e -c primary.ctx
 tpm2_create -G ecc:ecdsa  -g sha256  -u key.pub -r key.priv -C primary.ctx
 tpm2_load -C primary.ctx -u key.pub -r key.priv -c key.ctx
 tpm2_evictcontrol -C o -c key.ctx 0x81008002
```

#### Create CSR 

```bash
go run csrgen/csrgen.go --filename /tmp/server.csr --sni server.domain.com  --persistentHandle=0x81008001 --useECCRawFormat=false
```

#### Create self-signed cert with TPM based key

```bash
## for RSA keys
go run  certgen/certgen.go  --filename /tmp/server.crt --persistentHandle=0x81008001 --sni server.domain.com --cn=server.domain.com 

## for ECC keys
go run  certgen/certgen.go  --filename /tmp/server.crt --persistentHandle=0x81008002 --sni server.domain.com --cn=server.domain.com --useECCRawFormat=false
```


#### RSA Key with Policy

```bash
## for policyRSApersistentHandle

 tpm2_startauthsession -S session.dat
 tpm2_policypcr -S session.dat -l sha256:23  -L policy.dat
 tpm2_flushcontext session.dat
 tpm2_createprimary -C o -c primary2.ctx
 tpm2_create -G rsa2048:rsassa:null -g sha256 -u rsa2.pub -r rsa2.priv -C primary2.ctx  -L policy.dat
 tpm2_load -C primary2.ctx -u rsa2.pub -r rsa2.priv -c rsa2.ctx
 tpm2_evictcontrol -C o -c rsa2.ctx 0x81008004


go run tpm_selfsigned_policy/main.go  --persistentHandle=0x81008004 
```

