package main

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"log"

	salkms "github.com/salrashid123/signer/kms"
)

var ()

func main() {

	stringToSign := "foo"
	fmt.Printf("Data to sign %s\n", stringToSign)

	b := []byte(stringToSign)

	h := sha256.New()
	h.Write(b)
	digest := h.Sum(nil)

	r, err := salkms.NewKMSCrypto(&salkms.KMS{
		ProjectId:          "core-eso",
		LocationId:         "us-central1",
		KeyRing:            "kr",
		Key:                "rskey1",
		KeyVersion:         "1",
		SignatureAlgorithm: x509.SHA256WithRSA,
	})
	// r, err := salkms.NewKMSCrypto(&salkms.KMS{
	// 	ProjectId:          "core-eso",
	// 	LocationId:         "us-central1",
	// 	KeyRing:            "kr",
	// 	Key:                "rskey2",
	// 	KeyVersion:         "1",
	// 	SignatureAlgorithm: x509.SHA256WithRSAPSS,
	// })
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

	// rsa-sign-pkcs1-2048-sha256
	err = rsa.VerifyPKCS1v15(rsaPubKey, crypto.SHA256, digest, s)
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Printf("Signed String verified\n")

	// rsa-sign-pss-2048-sha256

	// // // For PSS, the salt length used is equal to the length of digest algorithm.
	// err = rsa.VerifyPSS(rsaPubKey, crypto.SHA256, digest[:], s, &rsa.PSSOptions{
	// 	SaltLength: rsa.PSSSaltLengthEqualsHash,
	// 	Hash:       crypto.SHA256,
	// })
	// if err != nil {
	// 	fmt.Println(err)
	// 	return
	// }
	// fmt.Printf("Signed String verified\n")

	//  ec-sign-p256-sha256
	ecr, err := salkms.NewKMSCrypto(&salkms.KMS{
		ProjectId:          "core-eso",
		LocationId:         "us-central1",
		KeyRing:            "kr",
		Key:                "ec1",
		KeyVersion:         "1",
		SignatureAlgorithm: x509.ECDSAWithSHA256,
	})
	if err != nil {
		fmt.Println(err)
		return
	}
	epub := ecr.Public().(*ecdsa.PublicKey)
	es, err := ecr.Sign(rand.Reader, digest, crypto.SHA256)
	if err != nil {
		log.Println(err)
		return
	}
	fmt.Printf("Signed String: %s\n", base64.StdEncoding.EncodeToString(es))

	ecdsa.Verify(epub, digest, epub.X, epub.Y)
	if !ok {
		fmt.Printf("ECDSA Signed String failed\n")
	}
	fmt.Printf("ECDSA Signed String verified\n")
}
