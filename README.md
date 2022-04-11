#### crypto.Signer, implementations for Google Cloud KMS and Trusted Platform Modules

for private keys based on 

* Google Cloud KMS 
* Trusted Platform Module

- `kms/`:  Sample that implements `crypto.Signer` using Google Cloud KMS
- `tpm/`:  Sample that implements `crypto.Signer`  using `go-tpm` library for Trusted Platform Module
- `vault/`:  `crypto.Signer` for use with [Hashicorp Vault PKI Secrets](https://www.vaultproject.io/docs/secrets/pki)
- `pem/`:  Sample that implements `crypto.Signer`  They key file this mode accepts is RSA private key. THis is nothing new..you can ofcourse do this absolutely without this!...i just have it here as an example
- `certgen/`:  Library that generates a self-signed x509 certificate for the KMS and TPM based signers above
- `csrgen/`:  Library that generates a CSR using the key in KMS or TPM 

Also see:

- [GCS signedURLs and GCP Authentication with Trusted Platform Module](https://github.com/salrashid123/gcs_tpm)


### Usage Signer

Initialize a signer and directly use `.sign()` as shown in this sample for GCS SignedURL:

- [GCS SignedURL for KMS](https://github.com/salrashid123/kms_service_accounts/blob/master/main.go#L56)

### Usage TLS

see `example/mtls` folder

* for vault see [mTLS using Hashcorp Vault's PKI Secrets](https://github.com/salrashid123/vault_pki_mtls))
* for tpm see [mTLS with TPM bound private key](https://github.com/salrashid123/go_tpm_https_embed)
* for kms see [mTLS with Google Cloud KMS](https://github.com/salrashid123/kms_golang_signer)

### Sign/Verify PSS

see `example/sign_verify` folder


### Usage: Generate self-signed certificate

see `util/certgen/`

```
go run certgen/certgen.go -cn server.domain.com
```

### Usage: Generate CSR

see `util/csrgen/`

```
go run certgen/certgen.go -cn server.domain.com
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

	sal "github.com/salrashid123/signer/pem"
)

const (

)

var ()

func main() {
	t, err := salpem.NewPEMCrypto(&salpem.PEM{
		PrivatePEMFile: "server.key",
	})
	if err != nil {
		log.Fatal(err)
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

see [GCS signedURLs and GCP Authentication with Trusted Platform Module](https://github.com/salrashid123/gcs_tpm)

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