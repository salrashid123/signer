package main

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"flag"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"os"
	"slices"

	"github.com/google/go-tpm-tools/simulator"
	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/google/go-tpm/tpmutil"
	saltpm "github.com/salrashid123/signer/tpm"
)

const ()

/*


## ecc
	tpm2_createprimary -C o -G rsa2048:aes128cfb -g sha256 -c primary.ctx -a 'restricted|decrypt|fixedtpm|fixedparent|sensitivedataorigin|userwithauth|noda'
	tpm2_create -G ecc:ecdsa  -g sha256  -u key.pub -r key.priv -C primary.ctx  --format=pem --output=ecc_public.pem
	tpm2_flushcontext  -t
	tpm2_getcap  handles-transient
	tpm2_load -C primary.ctx -u key.pub -r key.priv -c key.ctx
	tpm2_evictcontrol -C o -c key.ctx 0x81008005
	tpm2_flushcontext  -t
*/

var (
	tpmPath = flag.String("tpm-path", "/dev/tpmrm0", "Path to the TPM device (character device or a Unix socket).")
	handle  = flag.Uint("handle", 0x81008001, "rsa Handle value")
)

var TPMDEVICES = []string{"/dev/tpm0", "/dev/tpmrm0"}

func OpenTPM(path string) (io.ReadWriteCloser, error) {
	if slices.Contains(TPMDEVICES, path) {
		return tpmutil.OpenTPM(path)
	} else if path == "simulator" {
		return simulator.GetWithFixedSeedInsecure(1073741825)
	} else {
		return net.Dial("tcp", path)
	}
}

func main() {

	flag.Parse()

	rwc, err := OpenTPM(*tpmPath)
	if err != nil {
		log.Fatalf("can't open TPM %q: %v", *tpmPath, err)
	}
	defer func() {
		if err := rwc.Close(); err != nil {
			log.Fatalf("can't close TPM %q: %v", *tpmPath, err)
		}
	}()

	rwr := transport.FromReadWriter(rwc)

	pub, err := tpm2.ReadPublic{
		ObjectHandle: tpm2.TPMHandle(*handle),
	}.Execute(rwr)
	if err != nil {
		log.Fatalf("error executing tpm2.ReadPublic %v", err)
	}

	stringToSign := "foo"
	fmt.Printf("Data to sign %s\n", stringToSign)

	b := []byte(stringToSign)

	h := sha256.New()
	h.Write(b)
	digest := h.Sum(nil)

	er, err := saltpm.NewTPMCrypto(&saltpm.TPM{
		TpmDevice: rwc,
		AuthHandle: &tpm2.AuthHandle{
			Handle: tpm2.TPMHandle(*handle),
			Name:   pub.Name,
			Auth:   tpm2.PasswordAuth(nil),
		},
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

	// now verify with ASN1 output format for ecc using library managed device
	erasn, err := saltpm.NewTPMCrypto(&saltpm.TPM{
		TpmDevice: rwc,
		AuthHandle: &tpm2.AuthHandle{
			Handle: tpm2.TPMHandle(*handle),
			Name:   pub.Name,
			Auth:   tpm2.PasswordAuth(nil),
		},
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
