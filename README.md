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
  When using the TPM for mTLS operations, make sure the Signature Hash thats received from the server uses `sha256`.  I've noticed that when TLSConfig is used against `nginx`, the Signing will fail as the Hash received with `crypto.SignerOpts` uses SHA512.
- `pem/`:  Sample that implements `crypto.Signer` and `crypto.Decrypter` using regular pem and x509 certificates. They key file this mode accepts is RSA private key.
- `certgen/`:  Library that generates a self-signed x509 certificate for the KMS and TPM based signers above
- `csrgen/`:  Library that generates a CSR using the key in KMS or TPM 


>> IMPORTANT: you must use at **MOST** go1.13 since versions beyond that uses RSA-PSS (ref [32425](https://github.com/golang/go/issues/32425)) and atleast KMS only support RSA

### Usage Signer

Initialize a signer and directly use `.sign()` as shown in this sample for GCS SignedURL:

- [GCS SignedURL for KMS](https://github.com/salrashid123/kms_service_accounts/blob/master/main.go#L56)

### Usage TLS

```golang
import (
	salkms "github.com/salrashid123/signer/kms"
	saltpm "github.com/salrashid123/signer/tpm"
	salpem "github.com/salrashid123/signer/pem"
	salvault "github.com/salrashid123/signer/vault"
)

	c, err := saltpm.NewTPMCrypto(&saltpm.TPM{
		 TpmDevice: "/dev/tpm0",
		 // Define either a persistent handle or a key reference file.  eg: 
		 // https://github.com/salrashid123/tpm2/blob/master/utils/importExternalRSA.go
		 //TpmHandle: 0x81010002,
		 TpmHandleFile: "/path/to/key.bin", 
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
		ExtTLSConfig: &tls.Config{
			ClientAuth: tls.RequireAndVerifyClientCert,
		},

	})	

	// for TLS
	caCert, err := ioutil.ReadFile("CA_crt.pem")
	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)

	clientCaCert, err := ioutil.ReadFile("CA_crt.pem")
	clientCaCertPool := x509.NewCertPool()
	clientCaCertPool.AppendCertsFromPEM(clientCaCert)

	r, err := sal.NewPEMCrypto(&sal.PEM{
		PublicCertFile: "server.crt",  // TLS requres x509
		//PublicPEMFile:  "server.pem",  // not required 
		PrivatePEMFile: "server.key",
		//ExtTLSConfig: &tls.Config{
		//  RootCAs:        caCertPool,	
		//	ClientCAs:      clientCaCertPool,
		//	ClientAuth:     tls.RequireAndVerifyClientCert,
		//},		
	})


```

### Usage CA (sign CSR)

Use the private key within KMS/TPM as a Certificate Authority to sign a certificate request:

- Create key, CSR

```bash
openssl genrsa -out server_key.pem 2048
openssl req -config /apps/CA/openssl.cnf -out server_csr.pem -key server_key.pem -new -sha256  -extensions v3_req  -subj "/C=US/ST=California/L=Mountain View/O=Google/OU=Enterprise/CN=sal.domain.com"
```

- Sign CSR

```golang
package main

import (
	"crypto/rand"
	"crypto/x509/pkix"
	"os"
	"crypto/x509"
	"encoding/pem"
	"io/ioutil"
	"log"
	"math/big"
	"time"

	sal "github.com/salrashid123/signer/kms"
)

const (
	projectID = "yourproject"
)

var ()

func main() {
	t, err := sal.NewKMSCrypto(&sal.KMS{
		ProjectId:  projectID,
		LocationId: "us-central1",
		KeyRing:    "mycacerts",
		Key:        "server",
		KeyVersion: "2",
	})
	if err != nil {
		log.Println(err)
		return
	}

	var notBefore time.Time
	notBefore = time.Now()

	notAfter := notBefore.Add(time.Hour * 24 * 365)

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		log.Fatalf("Failed to generate serial number: %s", err)
	}

	clientCSRFile, err := ioutil.ReadFile("server_csr.pem")
	if err != nil {
		panic(err)
	}
	pemBlock, _ := pem.Decode(clientCSRFile)
	if pemBlock == nil {
		panic("pem.Decode failed")
	}
	clientCSR, err := x509.ParseCertificateRequest(pemBlock.Bytes)
	if err != nil {
		panic(err)
	}
	if err = clientCSR.CheckSignature(); err != nil {
		panic(err)
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: clientCSR.Subject.Organization,
			CommonName:   clientCSR.Subject.CommonName,
		},

		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		IsCA:                  false,
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, clientCSR.PublicKey, t)
	if err != nil {
		log.Fatalf("Failed to create certificate: %s", err)
	}
	certOut, err := os.Create("cert.pem")
	if err != nil {
		log.Fatalf("Failed to open cert.pem for writing: %s", err)
	}
	if err := pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes}); err != nil {
		log.Fatalf("Failed to write data to cert.pem: %s", err)
	}
	if err := certOut.Close(); err != nil {
		log.Fatalf("Error closing cert.pem: %s", err)
	}
	log.Print("wrote cert.pem\n")

}
```

- Run

```
go run main.go
```

- Verify key and public cert match

```bash
$ openssl rsa -modulus -noout -in server_key.pem | openssl md5
(stdin)= e7a19d3ea6bba99a21c2b5372ca772d3

$ openssl x509 -modulus -noout -in cert.pem | openssl md5
(stdin)= e7a19d3ea6bba99a21c2b5372ca772d3
```

```bash
$ openssl x509 -in cert.pem -text -noout
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number:
            85:45:91:fa:49:91:e4:4f:81:e2:34:f8:5c:37:84:d9
        Signature Algorithm: sha256WithRSAEncryption
        Issuer: O = Google, CN = sal.domain.com
        Validity
            Not Before: Jan  7 17:59:12 2020 GMT
            Not After : Jan  6 17:59:12 2021 GMT
        Subject: O = Google, CN = sal.domain.com
```


### Usage GCS SignedURL

You can use any of the `crypto.Signer` implementations to generate a [GCS SignedURL](https://cloud.google.com/storage/docs/access-control/signed-urls).  Simply pass in the bytes to sign into a signer:

```golang
package main

import (
...
	sal "github.com/salrashid123/signer/pem"
	"cloud.google.com/go/storage"
...
)

var (
	projectId  = "project"
	bucketName = "yorubucket"
)


func main() {

	r, err := sal.NewPEMCrypto(&sal.PEM{
		PrivatePEMFile: "/path/to/rsa-privatekey.pem",
	})
	if err != nil {
		log.Println(err)
		return
	}

	object := "foo.txt"
	expires := time.Now().Add(time.Minute * 10)
	key := "your-service-account@project.iam.gserviceaccount.com"

	s, err := storage.SignedURL(bucketName, object, &storage.SignedURLOptions{
		Scheme:         storage.SigningSchemeV4,
		GoogleAccessID: key,
		SignBytes: func(b []byte) ([]byte, error) {
			sum := sha256.Sum256(b)
			return r.Sign(rand.Reader, sum[:], crypto.SHA256)
		},
		Method:  "GET",
		Expires: expires,
	})
	if err != nil {
		log.Fatal(err)
	}
	log.Println(s)

	resp, err := http.Get(s)
	if err != nil {
		panic(err)
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	log.Println("SignedURL Response :\n", string(body))
	if err != nil {
		log.Fatal(err)
	}

}

```

If you have a GCP Service Account in PEM format, you need to convert the key to RSA:
```
$ openssl rsa -in sa_key.pem  -out sa_key-rsa.pem
```