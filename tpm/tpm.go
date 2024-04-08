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
)

const ()

var ()

// Configures and manages Singer configuration
//

type TPM struct {
	crypto.Signer

	Key            *client.Key        // load a key from handle
	TpmDevice      io.ReadWriteCloser // TPM Device path /dev/tpm0
	ECCRawOutput   bool               // for ECC keys, output raw signatures. If false, signature is ans1 formatted
	refreshMutex   sync.Mutex
	PublicCertFile string      // a provided public x509 certificate for the signer
	ExtTLSConfig   *tls.Config // override tls.Config values

	x509Certificate x509.Certificate
	publicKey       crypto.PublicKey
}

// Configure a new TPM crypto.Signer

func NewTPMCrypto(conf *TPM) (TPM, error) {

	if conf.TpmDevice == nil || conf.Key == nil {
		return TPM{}, fmt.Errorf(" TpmDevice and Key must be set")
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
		pub, _, _, err := tpm2.ReadPublic(t.TpmDevice, t.Key.Handle())
		if err != nil {
			fmt.Printf("google: Unable to Read Public data from TPM: %v", err)
			return fmt.Errorf("fmt: Unable to Read Public data from TPM: %v", err)
		}
		pubKey, err := pub.Key()
		if err != nil {
			fmt.Printf("google: Unable to Read Public data from TPM: %v", err)
			return fmt.Errorf("fmt: unable to Read Public data from TPM: %v", err)
		}
		t.publicKey = pubKey
	}
	return t.publicKey
}

func (t TPM) Sign(rr io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	t.refreshMutex.Lock()
	defer t.refreshMutex.Unlock()

	var err error
	s, err := t.Key.GetSigner()
	if err != nil {
		fmt.Printf("Failed to get signer: %v", err)
		return nil, fmt.Errorf("sign:  Failed to get signer %v", err)
	}
	sig, err := s.Sign(rr, digest, opts)
	if err != nil {
		fmt.Printf("Failed to signer: %v", err)
		return nil, fmt.Errorf("sign:  Failed to signer %v", err)
	}

	switch t.Key.PublicKey().(type) {
	case *rsa.PublicKey:
		return sig, nil
	case *ecdsa.PublicKey:
		if t.ECCRawOutput {
			epub := t.Key.PublicKey().(*ecdsa.PublicKey)
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
		log.Printf("ERROR:  unsupported key type: %v", t.Key.PublicKey())
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
