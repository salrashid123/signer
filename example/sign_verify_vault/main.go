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

	salvault "github.com/salrashid123/signer/vault"
)

var ()

func main() {

	r, err := salvault.NewVaultCrypto(&salvault.Vault{
		VaultToken:         "s.HA5jPy9J1PT1gFJdU4gFpopW",
		KeyPath:            "transit/keys/key1",
		SignPath:           "transit/sign/key1",
		KeyVersion:         1,
		VaultCAcert:        "../certs/tls-ca-chain.pem",
		VaultAddr:          "https://vault.domain.com:8200",
		SignatureAlgorithm: x509.SHA256WithRSA,
	})
	if err != nil {
		fmt.Println(err)
		return
	}

	stringToSign := "foo"
	fmt.Printf("Data to sign SHA256WithRSA %s\n", stringToSign)

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

	err = rsa.VerifyPKCS1v15(r.Public().(*rsa.PublicKey), crypto.SHA256, digest, s)
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Printf("Signed String SHA256WithRSA verified\n")
	// PSS

	fmt.Println()
	rs, err := salvault.NewVaultCrypto(&salvault.Vault{
		VaultToken:         "s.HA5jPy9J1PT1gFJdU4gFpopW",
		KeyPath:            "transit/keys/key1",
		SignPath:           "transit/sign/key1",
		KeyVersion:         1,
		VaultCAcert:        "../certs/tls-ca-chain.pem",
		VaultAddr:          "https://vault.domain.com:8200",
		SignatureAlgorithm: x509.SHA256WithRSAPSS,
	})
	if err != nil {
		fmt.Println(err)
		return
	}

	// only auto is supported
	var ropts rsa.PSSOptions
	ropts.SaltLength = rsa.PSSSaltLengthAuto

	pss, err := rs.Sign(rand.Reader, digest, &ropts)
	if err != nil {
		log.Println(err)
		return
	}
	fmt.Printf("Signed SHA256WithRSAPSS String: %s\n", base64.StdEncoding.EncodeToString(pss))

	err = rsa.VerifyPSS(rs.Public().(*rsa.PublicKey), crypto.SHA256, digest, pss, &ropts)
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Printf("Signed String SHA256WithRSAPSS verified\n")
	/// *********************************************************

}
