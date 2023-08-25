package main

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	"os"

	"github.com/google/go-tpm-tools/client"

	"github.com/google/go-tpm/legacy/tpm2"
	"github.com/google/go-tpm/tpmutil"
)

const (
	emptyPassword   = ""
	defaultPassword = ""
)

var (
	tpmPath          = flag.String("tpm-path", "/dev/tpm0", "Path to the TPM device (character device or a Unix socket).")
	persistentHandle = flag.Uint("persistentHandle", 0x81008000, "Handle value")
	flush            = flag.String("flush", "all", "Flush existing handles")
	mode             = flag.String("mode", "gencert", "Mode:  gencert")
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
		os.Exit(1)
	}
	defer func() {
		if err := rwc.Close(); err != nil {
			fmt.Fprintf(os.Stderr, "can't close TPM %s: %v", *tpmPath, err)
			os.Exit(1)
		}
	}()

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

	var kk *client.Key
	var kh tpmutil.Handle
	// A) either use the AK

	// a1) Get Attestation Key
	// AttestationKeyRSA generates and loads a key from AKTemplateRSA in the ***Owner*** hierarchy.
	// kk, err = client.AttestationKeyRSA(rwc)
	// if err != nil {
	// 	fmt.Fprintf(os.Stderr, "can't AK %q: %v", tpmPath, err)
	// 	os.Exit(1)
	// }

	// a2) only if on a GCE instance
	// if you use the AK, the public key will be the same as
	// gcloud compute instances get-shielded-identity tpm-test --zone us-central1-a --format="value(signingKey.ekPub)"
	// kk, err = client.GceAttestationKeyRSA(rwc)
	// if err != nil {
	// 	fmt.Fprintf(os.Stderr, "can't AK %q: %v", tpmPath, err)
	// 	os.Exit(1)
	// }

	// get the keyhandle
	// kh = kk.Handle()
	// defer tpm2.FlushContext(rwc, kh)

	// B) or Create a new Key
	pcrList := []int{0}
	pcrSelection := tpm2.PCRSelection{Hash: tpm2.AlgSHA256, PCRs: pcrList}

	pkh, _, err := tpm2.CreatePrimary(rwc, tpm2.HandleOwner, pcrSelection, emptyPassword, emptyPassword, defaultKeyParams)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error creating Primary %v\n", err)
		os.Exit(1)
	}
	defer tpm2.FlushContext(rwc, pkh)

	privInternal, pubArea, _, _, _, err := tpm2.CreateKey(rwc, pkh, pcrSelection, defaultPassword, defaultPassword, rsaKeyParams)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error  CreateKey %v\n", err)
		os.Exit(1)
	}

	kh, _, err = tpm2.Load(rwc, pkh, defaultPassword, pubArea, privInternal)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error  loading hash key %v\n", err)
		os.Exit(1)
	}
	defer tpm2.FlushContext(rwc, kh)

	pHandle := tpmutil.Handle(*persistentHandle)
	if *evict {
		err = tpm2.EvictControl(rwc, "", tpm2.HandleOwner, pHandle, pHandle)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error Unable evict persistentHandle %v\n", err)
			os.Exit(1)
		}
		err = tpm2.EvictControl(rwc, "", tpm2.HandleOwner, kh, pHandle)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error Unable evict persistentHandle %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("======= Key persisted ========\n")
	}

	// Either way, load the Key we persisted

	kk, err = client.NewCachedKey(rwc, tpm2.HandleOwner, rsaKeyParams, pHandle)
	if err != nil {
		fmt.Fprintf(os.Stderr, "can't NewCachedKey %q: %v\n", *tpmPath, err)
		os.Exit(1)
	}

	pubKey := kk.PublicKey().(*rsa.PublicKey)
	akBytes, err := x509.MarshalPKIXPublicKey(pubKey)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ERROR:  could not get MarshalPKIXPublicKey: %v", err)
		os.Exit(1)
	}
	akPubPEM := pem.EncodeToMemory(
		&pem.Block{
			Type:  "PUBLIC KEY",
			Bytes: akBytes,
		},
	)

	fmt.Printf("Signing Public Key: \n%s\n", akPubPEM)

}
