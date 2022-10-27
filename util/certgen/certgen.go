// Copyright 2020 Google LLC.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"flag"
	"log"
	"math/big"
	"os"
	"time"

	salpem "github.com/salrashid123/signer/pem"
	//salkms "github.com/salrashid123/signer/kms"
	//saltpm "github.com/salrashid123/signer/tpm"
	//salvault "github.com/salrashid123/signer/vault"
)

/*
Utility function that will generate an x509 certificate using private keys embedded in either a TPM or KMS system.

Edit the Subject/CN values as needed as well as KeyUsage or with defaults

go run certgen.go -cn server.domain.com

Note: x509 certificates associated with a google cloud service account have the following specifications:

Issuer: CN = YOURServiceAccountName@PROJECT_ID.iam.gserviceaccount.com
Subject: CN = YOURServiceAccountName@PROJECT_ID.iam.gserviceaccount.com
X509v3 extensions:

	    X509v3 Key Usage: critical
	        Digital Signature
	    X509v3 Extended Key Usage: critical
			TLS Web Client Authentication

Note: if you use openssl TPM2-TSS engine, you can generate the key on the TPM and use openssl to generate the x509 cert

$ tpm2tss-genkey -a rsa private.tss
$ openssl req -new -x509 -engine tpm2tss -key private.tss -keyform engine -out public.crt  -subj "/CN=example.com/"
$ openssl x509 -pubkey -noout -in public.crt  > public.pem
$ openssl x509 -in public.crt -text -noout
*/
const ()

var (
	cfg = &certGenConfig{}
)

type certGenConfig struct {
	flCN       string
	flFileName string
	flSNI      string
}

func main() {

	// r, err := saltpm.NewTPMCrypto(&saltpm.TPM{
	// 	TpmDevice: "/dev/tpm0",
	// 	TpmHandle: 0x81010002,
	// })

	// r, err := salkms.NewKMSCrypto(&salkms.KMS{
	// 	ProjectId:          "mineral-minutia-820",
	// 	LocationId:         "us-central1",
	// 	KeyRing:            "kr",
	// 	Key:                "s",
	// 	KeyVersion:         "1",
	// 	SignatureAlgorithm: x509.SHA256WithRSA,
	// })

	// r, err := salvault.NewVaultCrypto(&salvault.Vault{
	// 	VaultToken:         "s.JWSYsGG4SsvsojZYyrRfKrUt",
	// 	KeyPath:            "transit/keys/key1",
	// 	SignPath:           "transit/sign/key1",
	// 	KeyVersion:         1,
	// 	VaultCAcert:        "../example/certs/tls-ca-chain.pem",
	// 	VaultAddr:          "https://vault.domain.com:8200",
	// 	SignatureAlgorithm: x509.SHA256WithRSA,
	// })

	r, err := salpem.NewPEMCrypto(&salpem.PEM{
		PrivatePEMFile: "../example/certs/client_rsa.key",
	})

	if err != nil {
		log.Fatal(err)
	}

	createSelfSignedPubCert(r)

}

func createSelfSignedPubCert(t crypto.Signer) error {

	flag.StringVar(&cfg.flCN, "cn", "", "(required) CN= value for the certificate")
	flag.StringVar(&cfg.flFileName, "filename", "cert.pem", "Filename to save the generated cert")
	flag.Parse()

	argError := func(s string, v ...interface{}) {
		//flag.PrintDefaults()
		log.Fatalf("Invalid Argument error: "+s, v...)
	}
	if cfg.flCN == "" {
		argError("-cn not specified")
	}

	log.Printf("Creating public x509")

	var notBefore time.Time
	notBefore = time.Now()

	notAfter := notBefore.Add(time.Hour * 24 * 365)

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		log.Fatalf("Failed to generate serial number: %s", err)
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization:       []string{"Acme Co"},
			OrganizationalUnit: []string{"Enterprise"},
			Locality:           []string{"Mountain View"},
			Province:           []string{"California"},
			Country:            []string{"US"},
			CommonName:         cfg.flCN,
		},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		DNSNames:              []string{cfg.flCN},
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		IsCA:                  false,
	}

	ckey := t.Public().(*rsa.PublicKey)
	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, ckey, t)
	if err != nil {
		log.Fatalf("Failed to create certificate: %s", err)
	}
	certOut, err := os.Create(cfg.flFileName)
	if err != nil {
		log.Fatalf("Failed to open %s for writing: %s", cfg.flFileName, err)
	}
	if err := pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes}); err != nil {
		log.Fatalf("Failed to write data to %s: %s", cfg.flFileName, err)
	}
	if err := certOut.Close(); err != nil {
		log.Fatalf("Error closing %s  %s", cfg.flFileName, err)
	}
	log.Printf("wrote %s\n", cfg.flFileName)

	return nil
}
