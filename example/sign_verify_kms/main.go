package main

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
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
		ProjectId:  "mineral-minutia-820",
		LocationId: "us-central1",
		KeyRing:    "kr",
		Key:        "s",
		KeyVersion: "1",
		// SignatureAlgorithm: x509.SHA256WithRSAPSS,
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

	err = rsa.VerifyPKCS1v15(rsaPubKey, crypto.SHA256, digest, s)
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Printf("Signed String verified\n")

	// PSS ******************

	// // // For PSS, the salt length used is equal to the length of digest algorithm.
	// err = rsa.VerifyPSS(rsaPubKey, crypto.SHA256, digest[:], s2, &rsa.PSSOptions{
	// 	SaltLength: rsa.PSSSaltLengthEqualsHash,
	// 	Hash:       crypto.SHA256,
	// })
	// if err != nil {
	// 	fmt.Println(err)
	// 	return
	// }
	// fmt.Printf("Signed String verified\n")

}
