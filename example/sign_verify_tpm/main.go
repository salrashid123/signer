package main

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
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

var (
	tpmPath          = flag.String("tpm-path", "/dev/tpm0", "Path to the TPM device (character device or a Unix socket).")
	persistentHandle = flag.Uint("persistentHandle", 0x81008000, "Handle value")
	flush            = flag.String("flush", "all", "Flush existing handles")
	evict            = flag.Bool("evict", false, "Evict prior handle")
	handleNames      = map[string][]tpm2.HandleType{
		"all":       {tpm2.HandleTypeLoadedSession, tpm2.HandleTypeSavedSession, tpm2.HandleTypeTransient},
		"loaded":    {tpm2.HandleTypeLoadedSession},
		"saved":     {tpm2.HandleTypeSavedSession},
		"transient": {tpm2.HandleTypeTransient},
	}

	defaultKeyParams = tpm2.Public{
		Type:    tpm2.AlgRSA,
		NameAlg: tpm2.AlgSHA256,
		Attributes: tpm2.FlagFixedTPM | tpm2.FlagFixedParent | tpm2.FlagSensitiveDataOrigin |
			tpm2.FlagUserWithAuth | tpm2.FlagRestricted | tpm2.FlagDecrypt,
		AuthPolicy: []byte{},
		RSAParameters: &tpm2.RSAParams{
			Symmetric: &tpm2.SymScheme{
				Alg:     tpm2.AlgAES,
				KeyBits: 128,
				Mode:    tpm2.AlgCFB,
			},
			KeyBits: 2048,
		},
	}

	rsaKeyParams = tpm2.Public{
		Type:    tpm2.AlgRSA,
		NameAlg: tpm2.AlgSHA256,
		Attributes: tpm2.FlagFixedTPM | tpm2.FlagFixedParent | tpm2.FlagSensitiveDataOrigin |
			tpm2.FlagUserWithAuth | tpm2.FlagSign,
		AuthPolicy: []byte{},
		RSAParameters: &tpm2.RSAParams{
			Sign: &tpm2.SigScheme{
				Alg:  tpm2.AlgRSASSA,
				Hash: tpm2.AlgSHA256,
			},
			KeyBits: 2048,
		},
	}
)

func main() {

	flag.Parse()

	rwc, err := tpm2.OpenTPM(*tpmPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Can't open TPM %s: %v", *tpmPath, err)
		return
	}

	totalHandles := 0
	for _, handleType := range handleNames[*flush] {
		handles, err := client.Handles(rwc, handleType)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error getting handles", *tpmPath, err)
			os.Exit(1)
		}
		for _, handle := range handles {
			if err = tpm2.FlushContext(rwc, handle); err != nil {
				fmt.Fprintf(os.Stderr, "Error flushing handle 0x%x: %v\n", handle, err)
				os.Exit(1)
			}
			fmt.Printf("Handle 0x%x flushed\n", handle)
			totalHandles++
		}
	}

	pcrList := []int{0}
	pcrSelection := tpm2.PCRSelection{Hash: tpm2.AlgSHA256, PCRs: pcrList}

	pkh, _, err := tpm2.CreatePrimary(rwc, tpm2.HandleOwner, pcrSelection, emptyPassword, emptyPassword, defaultKeyParams)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error creating Primary %v\n", err)
		return
	}

	privInternal, pubArea, _, _, _, err := tpm2.CreateKey(rwc, pkh, pcrSelection, defaultPassword, defaultPassword, rsaKeyParams)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error  CreateKey %v\n", err)
		os.Exit(1)
	}
	newHandle, _, err := tpm2.Load(rwc, pkh, defaultPassword, pubArea, privInternal)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error  loading  key handle%v\n", err)
		os.Exit(1)
	}
	tpm2.FlushContext(rwc, pkh)
	defer tpm2.FlushContext(rwc, newHandle)
	pHandle := tpmutil.Handle(uint32(*persistentHandle))
	defer tpm2.FlushContext(rwc, pHandle)
	if *evict {
		fmt.Printf("======= Evicting Handles ========\n")
		err = tpm2.EvictControl(rwc, "", tpm2.HandleOwner, pHandle, pHandle)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error Unable evict persistentHandle %v\n", err)
			os.Exit(1)
		}

		err = tpm2.EvictControl(rwc, "", tpm2.HandleOwner, newHandle, pHandle)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error Unable to save persistentHandle %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("======= Key persisted ========\n")
	}

	err = rwc.Close()
	if err != nil {
		fmt.Fprintf(os.Stderr, "error closing tpm%v\n", err)
		os.Exit(1)
	}
	// ************************

	stringToSign := "foo"
	fmt.Printf("Data to sign %s\n", stringToSign)

	b := []byte(stringToSign)

	h := sha256.New()
	h.Write(b)
	digest := h.Sum(nil)

	r, err := saltpm.NewTPMCrypto(&saltpm.TPM{
		TpmDevice: *tpmPath,
		TpmHandle: uint32(*persistentHandle),
		//SignatureAlgorithm: x509.SHA256WithRSAPSS,
		SignatureAlgorithm: x509.SHA256WithRSA,
	})
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
		return
	}
	fmt.Printf("Signed String verified\n")

}
