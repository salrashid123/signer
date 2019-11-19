package main

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"log"
	"math/big"
	"os"
	"time"

	salkms "github.com/salrashid123/misc/kms"
)

const ()

var ()

func main() {

	// c, err := saltpm.NewTPMCrypto(&saltpm.TPM{
	// 	TpmDevice: "/dev/tpm0",
	// 	TpmHandle: 0x81010002,
	// })

	r, err := salkms.NewKMSCrypto(&salkms.KMS{
		ProjectId:  "mineral-minutia-820",
		LocationId: "us-central1",
		KeyRing:    "mykeyring",
		Key:        "rsign",
		KeyVersion: "1",
	})
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
			Organization: []string{"Acme Co"},
			CommonName:   "server.domain.com",
		},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		DNSNames:              []string{"server.domain.com"},
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

	return nil
}
