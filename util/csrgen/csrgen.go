// Copyright 2020 Google LLC.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"crypto"
	"crypto/rand"
	"io"
	"net"
	"slices"

	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"flag"
	"log"

	"os"

	"github.com/google/go-tpm-tools/simulator"
	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpmutil"

	saltpm "github.com/salrashid123/signer/tpm"
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

var TPMDEVICES = []string{"/dev/tpm0", "/dev/tpmrm0"}

func OpenTPM(path string) (io.ReadWriteCloser, error) {
	if slices.Contains(TPMDEVICES, path) {
		return tpmutil.OpenTPM(path)
	} else if path == "simulator" {
		return simulator.GetWithFixedSeedInsecure(1073741825)
	} else {
		return net.Dial("tcp", path)
	}
}

func main() {

	flag.Parse()

	rwc, err := OpenTPM(*tpmPath)
	if err != nil {
		log.Fatalf("can't open TPM %q: %v", *tpmPath, err)
	}
	defer func() {
		if err := rwc.Close(); err != nil {
			log.Fatalf("can't close TPM %q: %v", *tpmPath, err)
		}
	}()

	r, err := saltpm.NewTPMCrypto(&saltpm.TPM{
		TpmDevice:    rwc,
		Handle:       tpm2.TPMHandle(*persistentHandle),
		ECCRawOutput: *useECCRawFormat,
	})

	if err != nil {
		log.Fatal(err)
	}

	err = createCSR(r)
	if err != nil {
		log.Fatal(err)
	}

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
		//SignatureAlgorithm: x509.SHA256WithRSAPSS,
		SignatureAlgorithm: x509.SHA256WithRSA,
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
