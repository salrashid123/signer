package main

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
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

const ()

/*


## for eccpersistentHandle

 tpm2_createprimary -C e -c primary.ctx
 tpm2_create -G ecc:ecdsa  -g sha256  -u key.pub -r key.priv -C primary.ctx
 tpm2_load -C primary.ctx -u key.pub -r key.priv -c key.ctx
 tpm2_evictcontrol -C o -c key.ctx 0x81008002

## ECC
go run sign_verify_tpm/ecc/main.go --handle=0x81008002

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

	// >>>>>>>>>>>>>>>>>>>> Managed by library

	// ************************

	stringToSign := "foo"
	fmt.Printf("Data to sign %s\n", stringToSign)

	b := []byte(stringToSign)

	h := sha256.New()
	h.Write(b)
	digest := h.Sum(nil)

	er, err := saltpm.NewTPMCrypto(&saltpm.TPM{
		// managed externally
		TpmDevice:    rwc,
		Key:          k,
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

	curveBits := ecPubKey.Curve.Params().BitSize
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
	rwc.Close()
	k.Close()

	// now verify with ASN1 output format for ecc using library managed device
	erasn, err := saltpm.NewTPMCrypto(&saltpm.TPM{
		// manged by library
		TpmPath:   *tpmPath,
		KeyHandle: uint32(*handle),
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
