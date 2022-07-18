package main

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"log"

	salpem "github.com/salrashid123/signer/pem"
)

var ()

func main() {

	r, err := salpem.NewPEMCrypto(&salpem.PEM{
		PrivatePEMFile: "../certs/client_rsa.key",
		//SignatureAlgorithm: x509.SHA256WithRSAPSS,
	})
	if err != nil {
		fmt.Println(err)
		return
	}

	stringToSign := "foo"
	fmt.Printf("Data to sign %s\n", stringToSign)

	b := []byte(stringToSign)

	h := sha256.New()
	h.Write(b)
	digest := h.Sum(nil)

	s, err := r.Sign(rand.Reader, digest, crypto.SHA256)
	if err != nil {
		log.Println(err)
		return
	}
	fmt.Printf("Signed String: %s\n", base64.StdEncoding.EncodeToString(s))

	rc, err := ioutil.ReadFile("../certs/client.crt")
	if err != nil {
		fmt.Println(err)
		return
	}

	block, _ := pem.Decode(rc)

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		fmt.Println(err)
		return
	}

	rsaPubKey, ok := cert.PublicKey.(*rsa.PublicKey)
	if !ok {
		fmt.Println(err)
		return
	}

	err = rsa.VerifyPKCS1v15(rsaPubKey, crypto.SHA256, digest, s)
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Printf("Signed String verified\n")

	// var ropts rsa.PSSOptions
	// ropts.SaltLength = rsa.PSSSaltLengthEqualsHash

	// err = rsa.VerifyPSS(rsaPubKey, crypto.SHA256, digest, s, &ropts)
	// if err != nil {
	// 	fmt.Println(err)
	// 	return
	// }

	/// *********************************************************

}
