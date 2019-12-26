#### crypto.Signer, crypto.Decrypter implementations

for private keys based on 

* Google Cloud KMS 
* Trusted Platform Module
* HashiCorp Vault
* PEM key files

- `kms/`:  Sample that implements `crypto.Signer` and `crypto.Decrypter` using Google Cloud KMS
- `vault/`: Sample that implements `crypto.Signer` and `crypto.Decrypter` using the [PKI Secret Engine for HashiCorp Vault](https://www.vaultproject.io/docs/secrets/pki/index.html)
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
	salvault "github.com/salrashid123/signer/vault"
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

	r, err := salvault.NewVaultCrypto(&salvault.Vault{
		CertCN:      "server.domain.com",
		VaultToken:  "s.IumzeFZVsWqYcJ2IjlGaqZby",
		VaultPath:   "pki/issue/domain-dot-com",
		VaultCAcert: "CA_crt.pem",
		VaultAddr:   "https://vault.domain.com:8200",
		// ClientCAs:   clientCaCertPool,  // specified implicitly with vault CA
		ClientAuth:  tls.RequireAndVerifyClientCert,
	})	

	caCert, err := ioutil.ReadFile("CA_crt.pem")
	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)

	clientCaCert, err := ioutil.ReadFile("CA_crt.pem")
	clientCaCertPool := x509.NewCertPool()
	clientCaCertPool.AppendCertsFromPEM(clientCaCert)

	r, err := sal.NewPEMCrypto(&sal.PEM{
		PublicCertFile: "server.crt",  // TLS requres x509
		RootCAs:        caCertPool,
		//PublicPEMFile:  "server.pem",  // not required 
		PrivatePEMFile: "server.key",
		ClientCAs:      clientCaCertPool,
		ClientAuth:     tls.RequireAndVerifyClientCert,
	})


```