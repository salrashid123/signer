package main

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"flag"
	"fmt"
	"log"
	"os"

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
	tpmPath             = flag.String("tpm-path", "/dev/tpm0", "Path to the TPM device (character device or a Unix socket).")
	rsapersistentHandle = flag.Uint("rsapersistentHandle", 0x81008001, "rsa Handle value")
	eccpersistentHandle = flag.Uint("eccpersistentHandle", 0x81008002, "ecc Handle value")
)

func main() {

	flag.Parse()

	rwc, err := tpm2.OpenTPM(*tpmPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Can't open TPM %s: %v", *tpmPath, err)
		return
	}

	// ************************

	stringToSign := "foo"
	fmt.Printf("Data to sign %s\n", stringToSign)

	b := []byte(stringToSign)

	h := sha256.New()
	h.Write(b)
	digest := h.Sum(nil)
	pHandle := tpmutil.Handle(uint32(*rsapersistentHandle))
	k, err := client.LoadCachedKey(rwc, pHandle, nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error loading rsa key%v\n", err)
		os.Exit(1)
	}
	r, err := saltpm.NewTPMCrypto(&saltpm.TPM{
		TpmDevice:          rwc,
		Key:                k,
		SignatureAlgorithm: x509.SHA256WithRSA,
	})

	if err != nil {
		fmt.Println(err)
		return
	}

	s, err := r.Sign(rand.Reader, digest, crypto.SHA256)
	if err != nil {
		log.Println(err)
		return
	}
	fmt.Printf("RSA Signed String: %s\n", base64.StdEncoding.EncodeToString(s))

	rsaPubKey, ok := r.Public().(*rsa.PublicKey)
	if !ok {
		fmt.Println(err)
		return
	}

	// opts := &rsa.PSSOptions{
	// 	Hash:       crypto.SHA256,
	// 	SaltLength: rsa.PSSSaltLengthAuto,
	// }
	// err = rsa.VerifyPSS(rsaPubKey, crypto.SHA256, digest, s, opts)
	// if err != nil {
	// 	fmt.Println(err)
	// 	return
	// }

	err = rsa.VerifyPKCS1v15(rsaPubKey, crypto.SHA256, digest, s)
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Printf("RSA Signed String verified\n")

	//******************************************************************************************************

	eHandle := tpmutil.Handle(uint32(*eccpersistentHandle))
	ek, err := client.LoadCachedKey(rwc, eHandle, nil)

	if err != nil {
		fmt.Fprintf(os.Stderr, "error closing tpm%v\n", err)
		os.Exit(1)
	}
	er, err := saltpm.NewTPMCrypto(&saltpm.TPM{
		TpmDevice:          rwc,
		Key:                ek,
		SignatureAlgorithm: x509.ECDSAWithSHA256,
	})

	if err != nil {
		fmt.Println(err)
		return
	}
	es, err := er.Sign(rand.Reader, digest, crypto.SHA256)
	if err != nil {
		log.Println(err)
		return
	}
	fmt.Printf("ECC Signed String: %s\n", base64.StdEncoding.EncodeToString(es))

	ecPubKey, ok := er.Public().(*ecdsa.PublicKey)
	if !ok {
		log.Println("EKPublic key not found")
		return
	}

	epub := ek.PublicKey().(*ecdsa.PublicKey)
	ok = ecdsa.Verify(ecPubKey, digest[:], epub.X, epub.Y)
	if !ok {
		fmt.Printf("ECDSA Signed String failed\n")
	}
	fmt.Printf("ECDSA Signed String verified\n")
}
