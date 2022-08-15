package main

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"log"

	saltpm "github.com/salrashid123/signer/tpm"
)

var ()

func main() {

	stringToSign := "foo"
	fmt.Printf("Data to sign %s\n", stringToSign)

	b := []byte(stringToSign)

	h := sha256.New()
	h.Write(b)
	digest := h.Sum(nil)

	r, err := saltpm.NewTPMCrypto(&saltpm.TPM{
		TpmDevice: "/dev/tpm0",
		//TpmHandleFile: "/tmp/key.bin",
		//SignatureAlgorithm: x509.SHA256WithRSAPSS,
		SignatureAlgorithm: x509.SHA256WithRSA,
		TpmHandle:          0x81010002,
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
	fmt.Printf("Signed String: %s\n", base64.StdEncoding.EncodeToString(s))

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
	fmt.Printf("Signed String verified\n")

}
