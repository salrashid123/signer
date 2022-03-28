package main

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
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
		TpmDevice:     "/dev/tpm0",
		TpmHandleFile: "/tmp/key.bin",
		//TpmHandle:     0x81010002,
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

	// r2, err := salkms.NewKMSCrypto(&salkms.KMS{
	// 	ProjectId:          "mineral-minutia-820",
	// 	LocationId:         "us-central1",
	// 	KeyRing:            "kr",
	// 	Key:                "s2",
	// 	KeyVersion:         "1",
	// 	SignatureAlgorithm: x509.SHA256WithRSAPSS,
	// })
	// if err != nil {
	// 	fmt.Println(err)
	// 	return
	// }

	// s2, err := r2.Sign(rand.Reader, digest, &rsa.PSSOptions{
	// 	SaltLength: rsa.PSSSaltLengthEqualsHash,
	// 	Hash:       crypto.SHA256,
	// })
	// if err != nil {
	// 	log.Println(err)
	// 	return
	// }
	// fmt.Printf("PSS Signed String: %s\n", base64.StdEncoding.EncodeToString(s2))

	// rsaPubKey2, ok := r2.Public().(*rsa.PublicKey)
	// if !ok {
	// 	fmt.Println(err)
	// 	return
	// }

	// // // For PSS, the salt length used is equal to the length of digest algorithm.
	// err = rsa.VerifyPSS(rsaPubKey2, crypto.SHA256, digest[:], s2, &rsa.PSSOptions{
	// 	SaltLength: rsa.PSSSaltLengthEqualsHash,
	// 	Hash:       crypto.SHA256,
	// })
	// if err != nil {
	// 	fmt.Println(err)
	// 	return
	// }
	// fmt.Printf("Signed String verified\n")

}
