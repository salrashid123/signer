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

	"github.com/google/go-tpm-tools/client"
	"github.com/google/go-tpm/legacy/tpm2"
	"github.com/google/go-tpm/tpmutil"

	//salpem "github.com/salrashid123/signer/pem"
	saltpm "github.com/salrashid123/signer/tpm"
	//salkms "github.com/salrashid123/signer/kms"
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
	persistentHandle = flag.Uint("persistentHandle", 0x81008001, "rsa Handle value")
	useECCRawFormat  = flag.Bool("useECCRawFormat", false, "Test the session policy")
	cn               = flag.String("cn", "", "(required) CN= value for the certificate")
	filename         = flag.String("filename", "csr.pem", "Filename to save the generated csr")
	sni              = flag.String("sni", "server.domain.com", "SNI value in the csr generated csr")
	tpmPath          = flag.String("tpm-path", "/dev/tpm0", "Path to the TPM device (character device or a Unix socket).")
)

func main() {

	flag.Parse()

	rwc, err := tpm2.OpenTPM(*tpmPath)
	if err != nil {
		log.Fatal(err)
	}

	k, err := client.LoadCachedKey(rwc, tpmutil.Handle(*persistentHandle), nil)
	if err != nil {
		log.Fatal(err)
	}

	r, err := saltpm.NewTPMCrypto(&saltpm.TPM{
		TpmDevice:    rwc,
		Key:          k,
		ECCRawOutput: *useECCRawFormat,
	})

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

	// r, err := salpem.NewPEMCrypto(&salpem.PEM{
	// 	PrivatePEMFile: "../example/certs/client_rsa.key",
	// })
	if err != nil {
		log.Fatal(err)
	}

	createCSR(r)

}

func createCSR(t crypto.Signer) error {

	log.Printf("Creating CSR")

	var csrtemplate = x509.CertificateRequest{
		Subject: pkix.Name{
			Organization:       []string{"Acme Co"},
			OrganizationalUnit: []string{"Enterprise"},
			Locality:           []string{"Mountain View"},
			Province:           []string{"California"},
			Country:            []string{"US"},
			CommonName:         *cn,
		},
		DNSNames: []string{*sni},
	}

	csrBytes, err := x509.CreateCertificateRequest(rand.Reader, &csrtemplate, t)
	if err != nil {
		log.Fatalf("Failed to create CSR: %s", err)
	}
	certOut, err := os.Create(*filename)
	if err != nil {
		log.Fatalf("Failed to open %s for writing: %s", *filename, err)
	}
	if err := pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrBytes}); err != nil {
		log.Fatalf("Failed to write data to %s: %s", *filename, err)
	}
	if err := certOut.Close(); err != nil {
		log.Fatalf("Error closing %s  %s", *filename, err)
	}
	log.Printf("wrote %s\n", *filename)

	return nil
}
