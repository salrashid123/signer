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
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/google/go-tpm/tpmutil"

	saltpm "github.com/salrashid123/signer/tpm"
)

/*

## RSA - password with Endorsement RSA

	tpm2_flushcontext -t && tpm2_flushcontext -s && tpm2_flushcontext -l

	tpm2_createek -c ek.ctx -G rsa -u ek.pub

	tpm2 startauthsession --session session.ctx --policy-session
	tpm2 policysecret --session session.ctx --object-context endorsement

	tpm2_create -G rsa2048:rsassa:null -p bar -g sha256 -u key.pub -r key.priv -C ek.ctx  -P "session:session.ctx"
	tpm2_flushcontext -t && tpm2_flushcontext -s && tpm2_flushcontext -l

	tpm2 startauthsession --session session.ctx --policy-session
	tpm2 policysecret --session session.ctx --object-context endorsement
	tpm2_load -C ek.ctx -u key.pub -r key.priv -c key.ctx -P "session:session.ctx"
	tpm2_evictcontrol -C o -c key.ctx 0x81008006

	tpm2_flushcontext -t && tpm2_flushcontext -s && tpm2_flushcontext -l

	echo -n "foo" > /tmp/file.txt
	tpm2_sign -c key.ctx -g sha256 -f plain  -o signB.raw /tmp/file.txt -p bar
	xxd -p -c 100 signB.raw

go run sign_verify_tpm/policy_ek/main.go --handle="0x81008006"
*/

const (
	emptyPassword   = ""
	defaultPassword = ""
)

var (
	tpmPath = flag.String("tpm-path", "127.0.0.1:2341", "Path to the TPM device (character device or a Unix socket).")
	handle  = flag.Uint("handle", 0x81008008, "rsa Handle value")
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

	stringToSign := "foo"
	fmt.Printf("Data to sign %s\n", stringToSign)

	b := []byte(stringToSign)

	h := sha256.New()
	h.Write(b)
	digest := h.Sum(nil)

	primaryKey, err := tpm2.CreatePrimary{
		PrimaryHandle: tpm2.TPMRHEndorsement,
		InPublic:      tpm2.New2B(tpm2.RSAEKTemplate),
	}.Execute(rwr)
	if err != nil {
		log.Println(err)
		os.Exit(1)
	}

	defer func() {
		flushContextCmd := tpm2.FlushContext{
			FlushHandle: primaryKey.ObjectHandle,
		}
		_, _ = flushContextCmd.Execute(rwr)
	}()

	se, err := saltpm.NewPasswordSession(rwr, []byte("bar"), primaryKey.ObjectHandle)
	if err != nil {
		log.Println(err)
		os.Exit(1)
	}

	rr, err := saltpm.NewTPMCrypto(&saltpm.TPM{
		TpmDevice:   rwc,
		Handle:      tpm2.TPMHandle(*handle),
		AuthSession: se,
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
