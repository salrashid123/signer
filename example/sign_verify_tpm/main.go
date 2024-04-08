package main

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"flag"
	"fmt"
	"log"
	"math/big"
	"os"

	"github.com/google/go-tpm-tools/client"
	"github.com/google/go-tpm/legacy/tpm2"
	"github.com/google/go-tpm/tpmutil"

	saltpm "github.com/salrashid123/signer/tpm"
)

const (
	emptyPassword   = ""
	defaultPassword = ""
)

/*

## for rsapersistentHandle

 tpm2_createprimary -C e -c primary.ctx
 tpm2_create -G rsa2048:rsassa:null -g sha256 -u key.pub -r key.priv -C primary.ctx
 tpm2_load -C primary.ctx -u key.pub -r key.priv -c key.ctx
 tpm2_evictcontrol -C o -c key.ctx 0x81008001

## for eccpersistentHandle

 tpm2_createprimary -C e -c primary.ctx
 tpm2_create -G ecc:ecdsa  -g sha256  -u key.pub -r key.priv -C primary.ctx
 tpm2_load -C primary.ctx -u key.pub -r key.priv -c key.ctx
 tpm2_evictcontrol -C o -c key.ctx 0x81008002


## for policyRSApersistentHandle

 tpm2_startauthsession -S session.dat
 tpm2_policypcr -S session.dat -l sha256:23  -L policy.dat
 tpm2_flushcontext session.dat
 tpm2_createprimary -C o -c primary2.ctx
 tpm2_create -G rsa2048:rsassa:null -g sha256 -u rsa2.pub -r rsa2.priv -C primary2.ctx  -L policy.dat
 tpm2_load -C primary2.ctx -u rsa2.pub -r rsa2.priv -c rsa2.ctx
 tpm2_evictcontrol -C o -c rsa2.ctx 0x81008004


go run sign_verify_tpm/main.go --rsapersistentHandle=0x81008001
go run sign_verify_tpm/main.go --eccpersistentHandle=0x81008002
go run sign_verify_tpm/main.go --policyRSApersistentHandle=0x81008003
*/

var (
	tpmPath                   = flag.String("tpm-path", "/dev/tpm0", "Path to the TPM device (character device or a Unix socket).")
	rsapersistentHandle       = flag.Uint("rsapersistentHandle", 0, "rsa Handle value")
	eccpersistentHandle       = flag.Uint("eccpersistentHandle", 0, "ecc Handle value")
	policyRSApersistentHandle = flag.Uint("policyRSApersistentHandle", 0, "ecc Handle value")
	pcr                       = flag.Int("pcr", 23, "PCR value")
)

func main() {

	flag.Parse()

	rwc, err := tpm2.OpenTPM(*tpmPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Can't open TPM %s: %v", *tpmPath, err)
		return
	}

	// ************************

	stringToSign := "foo"
	fmt.Printf("Data to sign %s\n", stringToSign)

	b := []byte(stringToSign)

	h := sha256.New()
	h.Write(b)
	digest := h.Sum(nil)

	if *rsapersistentHandle != 0 {
		pHandle := tpmutil.Handle(uint32(*rsapersistentHandle))
		k, err := client.LoadCachedKey(rwc, pHandle, nil)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error loading rsa key%v\n", err)
			os.Exit(1)
		}
		r, err := saltpm.NewTPMCrypto(&saltpm.TPM{
			TpmDevice: rwc,
			Key:       k,
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
	}

	//******************************************************************************************************

	if *eccpersistentHandle != 0 {
		eHandle := tpmutil.Handle(uint32(*eccpersistentHandle))
		ek, err := client.LoadCachedKey(rwc, eHandle, nil)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error getting key tpm%v\n", err)
			os.Exit(1)
		}
		er, err := saltpm.NewTPMCrypto(&saltpm.TPM{
			TpmDevice:    rwc,
			Key:          ek,
			ECCRawOutput: true, // use raw output; not asn1
		})
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
		es, err := er.Sign(rand.Reader, digest, crypto.SHA256)
		if err != nil {
			log.Println(err)
			os.Exit(1)
		}
		fmt.Printf("ECC Signed String: %s\n", base64.StdEncoding.EncodeToString(es))

		ecPubKey, ok := er.Public().(*ecdsa.PublicKey)
		if !ok {
			log.Println("EKPublic key not found")
			return
		}
		epub := ek.PublicKey().(*ecdsa.PublicKey)

		curveBits := epub.Curve.Params().BitSize
		keyBytes := curveBits / 8
		if curveBits%8 > 0 {
			keyBytes += 1
		}

		x := big.NewInt(0).SetBytes(es[:keyBytes])
		y := big.NewInt(0).SetBytes(es[keyBytes:])

		ok = ecdsa.Verify(ecPubKey, digest[:], x, y)
		if !ok {
			fmt.Printf("ECDSA Signed String failed\n")
			os.Exit(1)
		}
		fmt.Printf("ECDSA Signed String verified\n")

		// now verify with ASN1 output format for ecc
		erasn, err := saltpm.NewTPMCrypto(&saltpm.TPM{
			TpmDevice: rwc,
			Key:       ek,
			//ECCRawOutput: false,
		})
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
		esasn, err := erasn.Sign(rand.Reader, digest, crypto.SHA256)
		if err != nil {
			log.Println(err)
			os.Exit(1)
		}
		fmt.Printf("ECC Signed String ASN1: %s\n", base64.StdEncoding.EncodeToString(esasn))

		ecPubKeyASN, ok := erasn.Public().(*ecdsa.PublicKey)
		if !ok {
			log.Println("EKPublic key not found")
			return
		}

		ok = ecdsa.VerifyASN1(ecPubKeyASN, digest[:], esasn)
		if !ok {
			fmt.Printf("ECDSA Signed String failed\n")
			os.Exit(1)
		}
		fmt.Printf("ECDSA Signed String verified\n")

	}

	//******************************************************************************************************

	if *policyRSApersistentHandle != 0 {

		s, err := client.NewPCRSession(rwc, tpm2.PCRSelection{tpm2.AlgSHA256, []int{*pcr}})
		if err != nil {
			log.Fatalf("Unable to initialize tpmJWT: %v", err)
		}

		rHandle := tpmutil.Handle(uint32(*policyRSApersistentHandle))
		rk, err := client.LoadCachedKey(rwc, rHandle, s)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error loading rsa key%v\n", err)
			os.Exit(1)
		}

		rr, err := saltpm.NewTPMCrypto(&saltpm.TPM{
			TpmDevice: rwc,
			Key:       rk,
		})

		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}

		rs, err := rr.Sign(rand.Reader, digest, crypto.SHA256)
		if err != nil {
			log.Println(err)
			os.Exit(1)
		}
		fmt.Printf("RSA Signed String: %s\n", base64.StdEncoding.EncodeToString(rs))

		rrsaPubKey, ok := rr.Public().(*rsa.PublicKey)
		if !ok {
			fmt.Println(err)
			os.Exit(1)
		}

		err = rsa.VerifyPKCS1v15(rrsaPubKey, crypto.SHA256, digest, rs)
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
		fmt.Printf("RSA Signed String verified\n")
	}

}
