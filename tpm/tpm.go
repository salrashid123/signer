// Copyright 2020 Google LLC.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Creates a crypto.Signer() for TPM based credentials
//   Support RSA, ECC and keys with policiyPCR
// Also fulfils TLSCertificate() interface for use with TLS

package tpm

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"math/big"
	"os"
	"sync"

	"github.com/google/go-tpm-tools/client"
	"github.com/google/go-tpm/legacy/tpm2"
	"github.com/google/go-tpm/tpmutil"
)

const ()

var ()

// Configures and manages Singer configuration
//

type TPM struct {
	crypto.Signer

	Key            *client.Key        // load a key from handle
	TpmDevice      io.ReadWriteCloser // TPM read closer
	TpmPath        string             // path to the ptm device /dev/tpm0
	KeyHandle      uint32             // path to the ptm device /dev/tpm0
	ECCRawOutput   bool               // for ECC keys, output raw signatures. If false, signature is ans1 formatted
	refreshMutex   sync.Mutex
	PublicCertFile string      // a provided public x509 certificate for the signer
	ExtTLSConfig   *tls.Config // override tls.Config values
	PCRs           []int

	x509Certificate x509.Certificate
	publicKey       crypto.PublicKey
}

// Configure a new TPM crypto.Signer

func NewTPMCrypto(conf *TPM) (TPM, error) {

	if conf.Key == nil && conf.KeyHandle == 0 {
		return TPM{}, fmt.Errorf("salrashid123/x/oauth2/google: Key or KeyHandle must be specified")
	}

	if conf.TpmDevice != nil && conf.TpmPath != "" {
		return TPM{}, fmt.Errorf("salrashid123/x/oauth2/google: one of TPMTokenConfig.TPMDevice,  TPMTokenConfig.TPMPath must be set")
	}

	if conf.TpmDevice != nil && conf.Key == nil {
		return TPM{}, fmt.Errorf("salrashid123/x/oauth2/google:  if TPMTokenConfig.TPMDevice is specified, a Key must be set")
	}

	if conf.TpmPath != "" && conf.KeyHandle == 0 {
		return TPM{}, fmt.Errorf("salrashid123/x/oauth2/google:  if TPMTokenConfig.TPMPath is specified, a KeyHandle must be set")
	}
	if conf.ExtTLSConfig != nil {
		if len(conf.ExtTLSConfig.Certificates) > 0 {
			return TPM{}, fmt.Errorf("certificates value in ExtTLSConfig Ignored")
		}

		if len(conf.ExtTLSConfig.CipherSuites) > 0 {
			return TPM{}, fmt.Errorf("cipherSuites value in ExtTLSConfig Ignored")
		}
	}
	return *conf, nil
}

func (t TPM) Public() crypto.PublicKey {
	if t.publicKey == nil {
		t.refreshMutex.Lock()
		defer t.refreshMutex.Unlock()

		var rwc io.ReadWriteCloser
		var k *client.Key
		if t.TpmDevice == nil {
			var err error
			rwc, err = tpm2.OpenTPM(t.TpmPath)
			if err != nil {
				fmt.Printf("google: Unable to Read Public data from TPM: %v", err)
				return nil
			}
			defer rwc.Close()
			pcrsession, err := client.NewPCRSession(rwc, tpm2.PCRSelection{tpm2.AlgSHA256, t.PCRs})
			if err != nil {
				fmt.Printf("google: Unable to Read Public data from TPM: %v", err)
				return nil
			}
			k, err = client.LoadCachedKey(rwc, tpmutil.Handle(t.KeyHandle), pcrsession)
			if err != nil {
				fmt.Printf("google: Unable to Read Public data from TPM: %v", err)
				return nil
			}
			defer pcrsession.Close()
			defer k.Close()
		} else {
			rwc = t.TpmDevice
			k = t.Key
		}

		pub, _, _, err := tpm2.ReadPublic(rwc, k.Handle())
		if err != nil {
			fmt.Printf("google: Unable to Read Public data from TPM: %v", err)
			return nil
		}
		pubKey, err := pub.Key()
		if err != nil {
			fmt.Printf("google: Unable to Read Public data from TPM: %v", err)
			return nil
		}
		t.publicKey = pubKey
	}
	return t.publicKey
}

func (t TPM) Sign(rr io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	t.refreshMutex.Lock()
	defer t.refreshMutex.Unlock()
	var rwc io.ReadWriteCloser
	var k *client.Key
	if t.TpmDevice == nil {
		var err error
		rwc, err = tpm2.OpenTPM(t.TpmPath)
		if err != nil {
			fmt.Printf("google: Unable to Read Public data from TPM: %v", err)
			return nil, fmt.Errorf("fmt: Unable to Read Public data from TPM: %v", err)
		}
		defer rwc.Close()
		pcrsession, err := client.NewPCRSession(rwc, tpm2.PCRSelection{tpm2.AlgSHA256, t.PCRs})
		if err != nil {
			fmt.Printf("google: Unable to Read Public data from TPM: %v", err)
			return nil, fmt.Errorf("fmt: Unable to Read Public data from TPM: %v", err)
		}
		k, err = client.LoadCachedKey(rwc, tpmutil.Handle(t.KeyHandle), pcrsession)
		if err != nil {
			fmt.Printf("google: Unable to Read Public data from TPM: %v", err)
			return nil, fmt.Errorf("fmt: Unable to Read Public data from TPM: %v", err)
		}
		defer pcrsession.Close()
		defer k.Close()
	} else {
		rwc = t.TpmDevice
		k = t.Key
	}
	var err error
	s, err := k.GetSigner()
	if err != nil {
		fmt.Printf("Failed to get signer: %v", err)
		return nil, fmt.Errorf("sign:  Failed to get signer %v", err)
	}

	if k.PublicArea().RSAParameters != nil {
		if k.PublicArea().RSAParameters.Sign.Alg == tpm2.AlgRSAPSS {
			h, err := t.Key.PublicArea().NameAlg.Hash()
			if err != nil {
				fmt.Printf("Failed to get hash for pss: %v", err)
				return nil, fmt.Errorf("sign:  hash for pss %v", err)
			}
			opts = &rsa.PSSOptions{
				Hash:       h,
				SaltLength: rsa.PSSSaltLengthAuto,
			}
		}
	}

	sig, err := s.Sign(rr, digest, opts)
	if err != nil {
		fmt.Printf("Failed to signer: %v", err)
		return nil, fmt.Errorf("sign:  Failed to signer %v", err)
	}

	switch k.PublicKey().(type) {
	case *rsa.PublicKey:
		return sig, nil
	case *ecdsa.PublicKey:
		if t.ECCRawOutput {
			epub := k.PublicKey().(*ecdsa.PublicKey)
			curveBits := epub.Params().BitSize
			keyBytes := curveBits / 8
			if curveBits%8 > 0 {
				keyBytes += 1
			}
			out := make([]byte, 2*keyBytes)
			var sigStruct struct{ R, S *big.Int }
			_, err := asn1.Unmarshal(sig, &sigStruct)
			if err != nil {
				return nil, fmt.Errorf("tpmjwt: can't unmarshall ecc struct %v", err)
			}
			sigStruct.R.FillBytes(out[0:keyBytes])
			sigStruct.S.FillBytes(out[keyBytes:])
			return out, nil
		}
		return sig, err
	default:
		log.Printf("ERROR:  unsupported key type: %v", k.PublicKey())
		return nil, fmt.Errorf("sign:  Failed to signer %v", err)
	}
}

func (t TPM) TLSCertificate() tls.Certificate {

	if t.PublicCertFile == "" {
		fmt.Printf("Public X509 certificate not specified")
		return tls.Certificate{}
	}

	pubPEM, err := os.ReadFile(t.PublicCertFile)
	if err != nil {
		fmt.Printf("Unable to read keys %v", err)
		return tls.Certificate{}
	}
	block, _ := pem.Decode([]byte(pubPEM))
	if block == nil {
		fmt.Printf("failed to parse PEM block containing the public key")
		return tls.Certificate{}
	}
	pub, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		fmt.Printf("failed to parse public key: " + err.Error())
		return tls.Certificate{}
	}

	t.x509Certificate = *pub
	var privKey crypto.PrivateKey = t
	return tls.Certificate{
		PrivateKey:  privKey,
		Leaf:        &t.x509Certificate,
		Certificate: [][]byte{t.x509Certificate.Raw},
	}
}

func (t TPM) TLSConfig() *tls.Config {

	return &tls.Config{
		Certificates: []tls.Certificate{t.TLSCertificate()},

		RootCAs:      t.ExtTLSConfig.RootCAs,
		ClientCAs:    t.ExtTLSConfig.ClientCAs,
		ClientAuth:   t.ExtTLSConfig.ClientAuth,
		ServerName:   t.ExtTLSConfig.ServerName,
		CipherSuites: t.ExtTLSConfig.CipherSuites,
		MaxVersion:   t.ExtTLSConfig.MaxVersion,
		MinVersion:   t.ExtTLSConfig.MinVersion,
	}
}
