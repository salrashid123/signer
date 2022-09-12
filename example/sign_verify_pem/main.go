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

	//salpem "github.com/salrashid123/signer/pem"
	salpem "github.com/salrashid123/signer/pem"
)

var ()

func main() {

	r, err := salpem.NewPEMCrypto(&salpem.PEM{
		PrivatePEMFile:     "certs/client_rsa.key",
		SignatureAlgorithm: x509.SHA256WithRSAPSS,
	})

	// // rsa.PrivateKey also implements a crypto.Signer
	// // https://pkg.go.dev/crypto/rsa#PrivateKey.Sign
	// privatePEM, err := ioutil.ReadFile("certs/client_rsa.key")
	// if err != nil {
	// 	fmt.Printf("error getting signer %v", err)
	// 	os.Exit(0)
	// }
	// rblock, _ := pem.Decode(privatePEM)
	// if rblock == nil {
	// 	fmt.Printf("error getting signer %v", err)
	// 	os.Exit(0)
	// }
	// r, err := x509.ParsePKCS1PrivateKey(rblock.Bytes)

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

	// rc, err := ioutil.ReadFile("certs/client.crt")
	// if err != nil {
	// 	fmt.Println(err)
	// 	return
	// }

	// block, _ := pem.Decode(rc)

	// cert, err := x509.ParseCertificate(block.Bytes)
	// if err != nil {
	// 	fmt.Println(err)
	// 	return
	// }

	// rsaPubKey, ok := cert.PublicKey.(*rsa.PublicKey)
	// if !ok {
	// 	fmt.Println(err)
	// 	return
	// }

	//err = rsa.VerifyPKCS1v15(rsaPubKey, crypto.SHA256, digest, s)
	// err = rsa.VerifyPKCS1v15(r.Public().(*rsa.PublicKey), crypto.SHA256, digest, s)
	// if err != nil {
	// 	fmt.Println(err)
	// 	return
	// }

	var ropts rsa.PSSOptions
	ropts.SaltLength = rsa.PSSSaltLengthEqualsHash

	err = rsa.VerifyPSS(r.Public().(*rsa.PublicKey), crypto.SHA256, digest, s, &ropts)
	if err != nil {
		fmt.Println(err)
		return
	}

	/// *********************************************************

	fmt.Printf("Signed String verified\n")
}
