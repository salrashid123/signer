// Copyright 2020 Google LLC.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"crypto"
	"crypto/rand"

	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"flag"
	"log"

	"os"

	salpem "github.com/salrashid123/signer/pem"
	//salkms "github.com/salrashid123/signer/kms"
	//saltpm "github.com/salrashid123/signer/tpm"
	//salvault "github.com/salrashid123/signer/vault"
)

/*
Utility function that will generate generates a CSR using private keys embedded in either a TPM or KMS system.

Edit the Subject/CN values as needed as well as KeyUsage or with defaults

go run csrgen.go -cn server.domain.com

Note: x509 certificates associated with a google cloud service account have the following specifications:

ref: Golang to generate and sign a certificate using a CA and to also sign a CSR

	https://gist.github.com/salrashid123/1fd267cf213c1a1fe9e6c35c78b47e83

// openssl rsa -in server_key.pem -pubout > server_rsa.pem
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

	createCSR(r)

}

func createCSR(t crypto.Signer) error {

	flag.StringVar(&cfg.flCN, "cn", "", "(required) CN= value for the certificate")
	flag.StringVar(&cfg.flFileName, "filename", "csr.pem", "Filename to save the generated csr")
	flag.Parse()

	argError := func(s string, v ...interface{}) {
		//flag.PrintDefaults()
		log.Fatalf("Invalid Argument error: "+s, v...)
	}
	if cfg.flCN == "" {
		argError("-cn not specified")
	}

	log.Printf("Creating CSR")

	var csrtemplate = x509.CertificateRequest{
		Subject: pkix.Name{
			Organization:       []string{"Acme Co"},
			OrganizationalUnit: []string{"Enterprise"},
			Locality:           []string{"Mountain View"},
			Province:           []string{"California"},
			Country:            []string{"US"},
			CommonName:         "server.domain.com",
		},
		DNSNames: []string{"server.domain.com"},
	}

	csrBytes, err := x509.CreateCertificateRequest(rand.Reader, &csrtemplate, t)
	if err != nil {
		log.Fatalf("Failed to create CSR: %s", err)
	}
	certOut, err := os.Create(cfg.flFileName)
	if err != nil {
		log.Fatalf("Failed to open %s for writing: %s", cfg.flFileName, err)
	}
	if err := pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrBytes}); err != nil {
		log.Fatalf("Failed to write data to %s: %s", cfg.flFileName, err)
	}
	if err := certOut.Close(); err != nil {
		log.Fatalf("Error closing %s  %s", cfg.flFileName, err)
	}
	log.Printf("wrote %s\n", cfg.flFileName)

	return nil
}
