package main

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/google/go-tpm-tools/client"
	"github.com/google/go-tpm/legacy/tpm2"
	"github.com/google/go-tpm/tpmutil"
	saltpm "github.com/salrashid123/signer/tpm"
)

const ()

/*

## for rsapersistentHandle

 tpm2_createprimary -C e -c primary.ctx
 tpm2_create -G rsa2048:rsassa:null -g sha256 -u key.pub -r key.priv -C primary.ctx
 tpm2_load -C primary.ctx -u key.pub -r key.priv -c key.ctx
 tpm2_evictcontrol -C o -c key.ctx 0x81008001


go run sign_verify_tpm/rsa/main.go --handle=0x81008001

*/

var (
	tpmPath = flag.String("tpm-path", "/dev/tpm0", "Path to the TPM device (character device or a Unix socket).")
	handle  = flag.Uint("handle", 0, "rsa Handle value")
)

func main() {

	flag.Parse()

	// >>>>>>>>>>>>>>>>>>>> Managed Externally

	// open a tpm and key if using externally managed handle
	rwc, err := tpm2.OpenTPM(*tpmPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Can't open TPM %s: %v", *tpmPath, err)
		return
	}

	pHandle := tpmutil.Handle(uint32(*handle))
	k, err := client.LoadCachedKey(rwc, pHandle, nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error loading rsa key%v\n", err)
		os.Exit(1)
	}

	stringToSign := "foo"
	fmt.Printf("Data to sign %s\n", stringToSign)

	b := []byte(stringToSign)

	h := sha256.New()
	h.Write(b)
	digest := h.Sum(nil)

	r, err := saltpm.NewTPMCrypto(&saltpm.TPM{
		// managed externally
		TpmDevice: rwc,
		Key:       k,

		// manged by library
		// TpmPath:   "/dev/tpm0",
		// KeyHandle: uint32(*handle),
	})

	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	s, err := r.Sign(rand.Reader, digest, crypto.SHA256)
	if err != nil {
		log.Println(err)
		os.Exit(1)
	}
	fmt.Printf("RSA Signed String: %s\n", base64.StdEncoding.EncodeToString(s))

	rsaPubKey, ok := r.Public().(*rsa.PublicKey)
	if !ok {
		fmt.Println(err)
		os.Exit(1)
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
		os.Exit(1)
	}
	fmt.Printf("RSA Signed String verified\n")

	k.Close()
	rwc.Close()

	// >>>>>>>>>>>>>>>>>>>> Managed by library

	// ***********************************************************************************************************

	r, err = saltpm.NewTPMCrypto(&saltpm.TPM{
		// manged by library
		TpmPath:   "/dev/tpm0",
		KeyHandle: uint32(*handle),
	})

	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	s, err = r.Sign(rand.Reader, digest, crypto.SHA256)
	if err != nil {
		log.Println(err)
		os.Exit(1)
	}
	fmt.Printf("RSA Signed String: %s\n", base64.StdEncoding.EncodeToString(s))

	rsaPubKey, ok = r.Public().(*rsa.PublicKey)
	if !ok {
		fmt.Println(err)
		os.Exit(1)
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
		os.Exit(1)
	}
	fmt.Printf("RSA Signed String verified\n")

}
