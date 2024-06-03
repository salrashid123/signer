package main

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"slices"

	"github.com/google/go-tpm-tools/simulator"
	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpmutil"
	saltpm "github.com/salrashid123/signer/tpm"
)

const ()

var (
	tpmPath = flag.String("tpm-path", "127.0.0.1:2321", "Path to the TPM device (character device or a Unix socket).")
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

	stringToSign := "foo"
	fmt.Printf("Data to sign %s\n", stringToSign)

	b := []byte(stringToSign)

	h := sha256.New()
	h.Write(b)
	digest := h.Sum(nil)

	r, err := saltpm.NewTPMCrypto(&saltpm.TPM{
		TpmPath:      *tpmPath,
		KeyHandle:    tpm2.TPMHandle(*handle).HandleValue(),
		PCRs:         []uint{},
		AuthPassword: []byte(""),
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

	err = rsa.VerifyPKCS1v15(rsaPubKey, crypto.SHA256, digest, s)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	fmt.Printf("RSA Signed String verified\n")

}
