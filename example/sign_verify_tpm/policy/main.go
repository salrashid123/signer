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

const (
	emptyPassword   = ""
	defaultPassword = ""
)

/*


## for policyRSApersistentHandle

 tpm2_startauthsession -S session.dat
 tpm2_policypcr -S session.dat -l sha256:23  -L policy.dat
 tpm2_flushcontext session.dat
 tpm2_createprimary -C o -c primary2.ctx
 tpm2_create -G rsa2048:rsassa:null -g sha256 -u rsa2.pub -r rsa2.priv -C primary2.ctx  -L policy.dat
 tpm2_load -C primary2.ctx -u rsa2.pub -r rsa2.priv -c rsa2.ctx
 tpm2_evictcontrol -C o -c rsa2.ctx 0x81008004


go run sign_verify_tpm/policy/main.go --handle=0x81008004
*/

var (
	tpmPath = flag.String("tpm-path", "/dev/tpm0", "Path to the TPM device (character device or a Unix socket).")
	handle  = flag.Uint("handle", 0, "rsa Handle value")
	pcr     = flag.Int("pcr", 23, "PCR value")
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
	stringToSign := "foo"
	fmt.Printf("Data to sign %s\n", stringToSign)

	b := []byte(stringToSign)

	h := sha256.New()
	h.Write(b)
	digest := h.Sum(nil)

	s, err := client.NewPCRSession(rwc, tpm2.PCRSelection{tpm2.AlgSHA256, []int{*pcr}})
	if err != nil {
		log.Fatalf("Unable to initialize tpmJWT: %v", err)
	}

	rHandle := tpmutil.Handle(uint32(*handle))
	rk, err := client.LoadCachedKey(rwc, rHandle, s)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error loading rsa key %v\n", err)
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

	s.Close()
	rk.Close()
	rwc.Close()

	// >>>>>>>>>>>>>>>>>>>> Managed by library
	// ******************************************************************

	rr, err = saltpm.NewTPMCrypto(&saltpm.TPM{
		TpmPath:   *tpmPath,
		KeyHandle: uint32(*handle),
		PCRs:      []int{23},
	})

	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	rs, err = rr.Sign(rand.Reader, digest, crypto.SHA256)
	if err != nil {
		log.Println(err)
		os.Exit(1)
	}
	fmt.Printf("RSA Signed String: %s\n", base64.StdEncoding.EncodeToString(rs))

	rrsaPubKey, ok = rr.Public().(*rsa.PublicKey)
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
