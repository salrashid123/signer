package main

import (
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"flag"
	"fmt"
	"log"
	"math/big"
	"os"
	"time"

	"github.com/google/go-tpm-tools/client"

	"github.com/google/go-tpm/legacy/tpm2"
	"github.com/google/go-tpm/tpmutil"
	saltpm "github.com/salrashid123/signer/tpm"
)

const (
	emptyPassword   = ""
	defaultPassword = ""
)

var (
	tpmPath          = flag.String("tpm-path", "/dev/tpm0", "Path to the TPM device (character device or a Unix socket).")
	persistentHandle = flag.Uint("persistentHandle", 0x81008000, "Handle value")
	pcr              = flag.Int("pcr", 23, "PCR value")
	flush            = flag.String("flush", "all", "Flush existing handles")
	evict            = flag.Bool("evict", false, "delete persistent handle")
	x509certFile     = flag.String("x509certFile", "x509cert.pem", "x509 certificate ")
	cn               = flag.String("cn", "OURServiceAccountName@PROJECT_ID.iam.gserviceaccount.com", "Common Name for the certificate ")

	handleNames = map[string][]tpm2.HandleType{
		"all":       {tpm2.HandleTypeLoadedSession, tpm2.HandleTypeSavedSession, tpm2.HandleTypeTransient},
		"loaded":    {tpm2.HandleTypeLoadedSession},
		"saved":     {tpm2.HandleTypeSavedSession},
		"transient": {tpm2.HandleTypeTransient},
	}

	defaultKeyParams = tpm2.Public{
		Type:    tpm2.AlgRSA,
		NameAlg: tpm2.AlgSHA256,
		Attributes: tpm2.FlagFixedTPM | tpm2.FlagFixedParent | tpm2.FlagSensitiveDataOrigin |
			tpm2.FlagUserWithAuth | tpm2.FlagRestricted | tpm2.FlagDecrypt,
		AuthPolicy: []byte{},
		RSAParameters: &tpm2.RSAParams{
			Symmetric: &tpm2.SymScheme{
				Alg:     tpm2.AlgAES,
				KeyBits: 128,
				Mode:    tpm2.AlgCFB,
			},
			KeyBits: 2048,
		},
	}

	rsaKeyParams = tpm2.Public{
		Type:    tpm2.AlgRSA,
		NameAlg: tpm2.AlgSHA256,
		Attributes: tpm2.FlagFixedTPM | tpm2.FlagFixedParent | tpm2.FlagSensitiveDataOrigin |
			tpm2.FlagUserWithAuth | tpm2.FlagSign,
		AuthPolicy: []byte{},
		RSAParameters: &tpm2.RSAParams{
			Sign: &tpm2.SigScheme{
				Alg:  tpm2.AlgRSASSA,
				Hash: tpm2.AlgSHA256,
			},
			KeyBits: 2048,
		},
	}
)

func main() {

	flag.Parse()

	rwc, err := tpm2.OpenTPM(*tpmPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Can't open TPM %s: %v", *tpmPath, err)
		os.Exit(1)
	}
	defer func() {
		if err := rwc.Close(); err != nil {
			fmt.Fprintf(os.Stderr, "can't close TPM %s: %v", *tpmPath, err)
			os.Exit(1)
		}
	}()

	totalHandles := 0
	for _, handleType := range handleNames[*flush] {
		handles, err := client.Handles(rwc, handleType)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error getting handles", *tpmPath, err)
			os.Exit(1)
		}
		for _, handle := range handles {
			if err = tpm2.FlushContext(rwc, handle); err != nil {
				fmt.Fprintf(os.Stderr, "Error flushing handle 0x%x: %v\n", handle, err)
				os.Exit(1)
			}
			fmt.Printf("Handle 0x%x flushed\n", handle)
			totalHandles++
		}
	}

	rHandle := tpmutil.Handle(*persistentHandle)
	fmt.Printf("======= Key persisted ========\n")
	fmt.Printf("======= Creating x509 Certificate ========\n")

	// https://raw.githubusercontent.com/salrashid123/signer/master/certgen/certgen.go

	var notBefore time.Time
	notBefore = time.Now()

	notAfter := notBefore.Add(time.Hour * 24 * 365)

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to generate serial number: %s", err)
		os.Exit(1)
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
		NotBefore: notBefore,
		NotAfter:  notAfter,
		DNSNames:  []string{*cn},
		KeyUsage:  x509.KeyUsageDigitalSignature,
		//ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		IsCA:                  false,
	}

	sess, err := client.NewPCRSession(rwc, tpm2.PCRSelection{tpm2.AlgSHA256, []int{*pcr}})
	if err != nil {
		log.Fatalf("Unable to initialize tpmJWT: %v", err)
	}
	defer sess.Close()
	rk, err := client.LoadCachedKey(rwc, rHandle, sess)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error loading rsa key%v\n", err)
		os.Exit(1)
	}

	s, err := saltpm.NewTPMCrypto(&saltpm.TPM{
		TpmDevice:    rwc,
		Key:          rk,
		ECCRawOutput: false,
	})

	if err != nil {
		fmt.Println(err)
		return
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, s.Public(), s)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to create certificate: %s\n", err)
		os.Exit(1)
	}
	certOut, err := os.Create(*x509certFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to open %s for writing: %s", *x509certFile, err)
		os.Exit(1)
	}
	if err := pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes}); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to write data to %s: %s", *x509certFile, err)
		os.Exit(1)
	}
	if err := certOut.Close(); err != nil {
		fmt.Fprintf(os.Stderr, "Error closing %s  %s", *x509certFile, err)
		os.Exit(1)
	}
	fmt.Fprintf(os.Stderr, "wrote %s\n", *x509certFile)

}
