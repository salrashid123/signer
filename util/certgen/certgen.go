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
	"io"
	"log"
	"math/big"
	"net"
	"os"
	"slices"
	"time"

	//salpem "github.com/salrashid123/signer/pem"
	//salkms "github.com/salrashid123/signer/kms"

	"github.com/google/go-tpm-tools/simulator"
	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/google/go-tpm/tpmutil"
	saltpm "github.com/salrashid123/signer/tpm"
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
	persistentHandle = flag.Uint("persistentHandle", 0x81008001, "rsa Handle value")

	useECCRawFormat = flag.Bool("useECCRawFormat", false, "Test the session policy")

	cn       = flag.String("cn", "", "(required) CN= value for the certificate")
	filename = flag.String("filename", "cert.pem", "Filename to save the generated csr")
	sni      = flag.String("sni", "server.domain.com", "SNI value in the csr generated csr")
	tpmPath  = flag.String("tpm-path", "/dev/tpm0", "Path to the TPM device (character device or a Unix socket).")
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

	rwr := transport.FromReadWriter(rwc)
	pub, err := tpm2.ReadPublic{
		ObjectHandle: tpm2.TPMHandle(*persistentHandle),
	}.Execute(rwr)
	if err != nil {
		log.Fatalf("error executing tpm2.ReadPublic %v", err)
	}
	r, err := saltpm.NewTPMCrypto(&saltpm.TPM{
		TpmDevice: rwc,
		NamedHandle: &tpm2.NamedHandle{
			Handle: tpm2.TPMHandle(*persistentHandle),
			Name:   pub.Name,
		},
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

	if err != nil {
		log.Fatal(err)
	}

	createSelfSignedPubCert(r)

}

func createSelfSignedPubCert(t crypto.Signer) error {

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
			CommonName:         *cn,
		},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		DNSNames:              []string{*sni},
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		IsCA:                  false,
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, t.Public(), t)
	if err != nil {
		log.Fatalf("Failed to create certificate: %s", err)
	}
	certOut, err := os.Create(*filename)
	if err != nil {
		log.Fatalf("Failed to open %s for writing: %s", *filename, err)
	}
	if err := pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes}); err != nil {
		log.Fatalf("Failed to write data to %s: %s", *filename, err)
	}
	if err := certOut.Close(); err != nil {
		log.Fatalf("Error closing %s  %s", *filename, err)
	}
	log.Printf("wrote %s\n", *filename)

	return nil
}
