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

	sal "github.com/salrashid123/signer/pem"
)

var ()

func main() {

	r, err := sal.NewPEMCrypto(&sal.PEM{
		PrivatePEMFile: "client.key",
		//SignatureAlgorithm: x509.SHA256WithRSAPSS,
	})
	if err != nil {
		fmt.Println(err)
		return
	}

	b := []byte("foo")

	h := sha256.New()
	h.Write(b)
	digest := h.Sum(nil)

	s, err := r.Sign(rand.Reader, digest, crypto.SHA256)
	if err != nil {
		log.Println(err)
		return
	}
	fmt.Printf("%s\n", base64.StdEncoding.EncodeToString(s))

	rc, err := ioutil.ReadFile("client.crt")
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

	// var ropts rsa.PSSOptions
	// ropts.SaltLength = rsa.PSSSaltLengthEqualsHash

	// err = rsa.VerifyPSS(rsaPubKey, crypto.SHA256, digest, s, &ropts)
	// if err != nil {
	// 	fmt.Println(err)
	// 	return
	// }

	/// *********************************************************

	hash := sha256.New()
	ciphertext, err := rsa.EncryptOAEP(hash, rand.Reader, rsaPubKey, b, nil)
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Printf("CipherText %s\n", base64.StdEncoding.EncodeToString(ciphertext))

	plaintext, err := r.Decrypt(rand.Reader, ciphertext, nil)
	if err != nil {
		fmt.Println(err)
		return
	}

	fmt.Println(string(plaintext))

}
