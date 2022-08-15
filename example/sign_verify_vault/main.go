package main

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"log"

	salvault "github.com/salrashid123/signer/vault"
)

var ()

func main() {

	r, err := salvault.NewVaultCrypto(&salvault.Vault{
		CertCN:      "client.domain.com",
		VaultToken:  "s.Mlu0TVNkfYh3GkE51r1i0kcv",
		VaultPath:   "pki/issue/domain-dot-com",
		VaultCAcert: "path/to/certs/ca/tls-ca.crt",
		VaultAddr:   "https://vault.domain.com:8200",
		// SignatureAlgorithm: x509.SHA256WithRSAPSS,
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

	err = rsa.VerifyPKCS1v15(r.Public().(*rsa.PublicKey), crypto.SHA256, digest, s)
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Printf("Signed String verified\n")

	// var ropts rsa.PSSOptions
	// ropts.SaltLength = rsa.PSSSaltLengthEqualsHash

	// err = rsa.VerifyPSS(r.Public().(*rsa.PublicKey), crypto.SHA256, digest, s, &ropts)
	// if err != nil {
	// 	fmt.Println(err)
	// 	return
	// }

	/// *********************************************************

}
