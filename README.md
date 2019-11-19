#### crypto.Signer, crypto.Decrypter implementations

for private keys based on 

* Google Cloud KMS 
* Trusted Platform Module
* PEM key files

- `kms/`:  Sample that implements `crypto.Signer` and `crypto.Decrypter` using Google Cloud KMS
- `tpm/`:  Sample that implements `crypto.Signer` and `crypto.Decrypter` using `go-tpm` library for Trusted Platform Module
```
    tpm2_createprimary -C e -g sha256 -G rsa -c primary.ctx
    tpm2_create -G rsa -u key.pub -r key.priv -C primary.ctx
    tpm2_load -C primary.ctx -u key.pub -r key.priv -c key.ctx
    tpm2_readpublic -c key.ctx -f PEM -o public.pem
    tpm2_evictcontrol -C o -c key.ctx 0x81010002 
```
- `pem/`:  Sample that implements `crypto.Signer` and `crypto.Decrypter` using regular pem can x509 certificates 
- `certgen/`:  Library that generates a self-signed x509 certificate for the KMS and TPM based signers above


Usage

```golang
import (
	salkms "github.com/salrashid123/signer/kms"
	saltpm "github.com/salrashid123/signer/tpm"
	salpem "github.com/salrashid123/signer/pem"
)

	c, err := saltpm.NewTPMCrypto(&saltpm.TPM{
	 	TpmDevice: "/dev/tpm0",
	 	TpmHandle: 0x81010002,
    })
    
	r, err := salkms.NewKMSCrypto(&salkms.KMS{
		ProjectId:  "mineral-minutia-820",
		LocationId: "us-central1",
		KeyRing:    "mykeyring",
		Key:        "rsign",
		KeyVersion: "1",
	})

	caCert, err := ioutil.ReadFile("CA_crt.pem")
	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)

	clientCaCert, err := ioutil.ReadFile("CA_crt.pem")
	clientCaCertPool := x509.NewCertPool()
	clientCaCertPool.AppendCertsFromPEM(clientCaCert)

	r, err := sal.NewPEMCrypto(&sal.PEM{

		PublicCertFile: "server.crt",
		RootCAs:        caCertPool,
		PublicPEMFile:  "server.pem",
		PrivatePEMFile: "server.key",
		ClientCAs:      clientCaCertPool,
		ClientAuth:     tls.RequireAndVerifyClientCert,
	})


```