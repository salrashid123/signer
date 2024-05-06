package main

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"fmt"
	"log"
	"math/big"

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
		ECCRawOutput:       false,
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

	ok = ecdsa.VerifyASN1(epub, digest[:], es)
	if !ok {
		log.Println(err)
		return
	}
	fmt.Printf("ECDSA Signed String verified as ASN1\n")

	// now verify signature as raw by converting the asn output to raw
	curveBits := epub.Curve.Params().BitSize
	keyBytes := curveBits / 8
	if curveBits%8 > 0 {
		keyBytes += 1
	}
	out := make([]byte, 2*keyBytes)
	var sigStruct struct{ R, S *big.Int }
	_, err = asn1.Unmarshal(es, &sigStruct)
	if err != nil {
		log.Println(err)
		return
	}
	sigStruct.R.FillBytes(out[0:keyBytes])
	sigStruct.S.FillBytes(out[keyBytes:])

	ok = ecdsa.Verify(epub, digest[:], sigStruct.R, sigStruct.S)
	if !ok {
		log.Printf("ECDSA Signed String failed\n")
		return
	}
	fmt.Printf("ECDSA Signed String verified RAW \n")

	// now sign/verify as RAW by setting the input flag

	ecrr, err := salkms.NewKMSCrypto(&salkms.KMS{
		ProjectId:          "core-eso",
		LocationId:         "us-central1",
		KeyRing:            "kr",
		Key:                "ec1",
		KeyVersion:         "1",
		SignatureAlgorithm: x509.ECDSAWithSHA256,
		ECCRawOutput:       true,
	})
	if err != nil {
		fmt.Println(err)
		return
	}

	esr, err := ecrr.Sign(rand.Reader, digest, crypto.SHA256)
	if err != nil {
		log.Println(err)
		return
	}
	fmt.Printf("Signed String RAW: %s\n", base64.StdEncoding.EncodeToString(esr))

	x := big.NewInt(0).SetBytes(esr[:keyBytes])
	y := big.NewInt(0).SetBytes(esr[keyBytes:])

	ok = ecdsa.Verify(epub, digest[:], x, y)
	if !ok {
		log.Printf("ECDSA Signed String failed\n")
		return
	}

	ok = ecdsa.Verify(epub, digest[:], sigStruct.R, sigStruct.S)
	if !ok {
		log.Printf("ECDSA Signed String failed\n")
		return
	}
	fmt.Printf("ECDSA Signed String verified RAW \n")

}
