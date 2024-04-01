// Copyright 2020 Google LLC.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tpm

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"
	"sync"

	"github.com/google/go-tpm-tools/client"
	"github.com/google/go-tpm/legacy/tpm2"
)

const ()

var (
	handleNames = map[string][]tpm2.HandleType{
		"all":       {tpm2.HandleTypeLoadedSession, tpm2.HandleTypeSavedSession, tpm2.HandleTypeTransient},
		"loaded":    {tpm2.HandleTypeLoadedSession},
		"saved":     {tpm2.HandleTypeSavedSession},
		"transient": {tpm2.HandleTypeTransient},
	}
)

type TPM struct {
	crypto.Signer

	Key                *client.Key
	TpmDevice          io.ReadWriteCloser
	FlushContext       bool
	SignatureAlgorithm x509.SignatureAlgorithm
	refreshMutex       sync.Mutex
	PublicCertFile     string
	ExtTLSConfig       *tls.Config

	x509Certificate x509.Certificate
	publicKey       crypto.PublicKey
}

func NewTPMCrypto(conf *TPM) (TPM, error) {

	if conf.SignatureAlgorithm == x509.UnknownSignatureAlgorithm {
		conf.SignatureAlgorithm = x509.SHA256WithRSA
	}
	if (conf.SignatureAlgorithm != x509.SHA256WithRSA) && (conf.SignatureAlgorithm != x509.SHA256WithRSAPSS && conf.SignatureAlgorithm != x509.ECDSAWithSHA256) {
		return TPM{}, fmt.Errorf("signatureALgorithm must be either x509.SHA256WithRSA or x509.SHA256WithRSAPSS or x509.ECDSAWithSHA256")
	}

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

	var signed *tpm2.Signature
	var err error
	if t.SignatureAlgorithm == x509.SHA256WithRSA {
		signed, err = tpm2.Sign(t.TpmDevice, t.Key.Handle(), "", digest[:], nil, &tpm2.SigScheme{
			Alg:  tpm2.AlgRSASSA,
			Hash: tpm2.AlgSHA256,
		})
	} else if t.SignatureAlgorithm == x509.SHA256WithRSAPSS {
		signed, err = tpm2.Sign(t.TpmDevice, t.Key.Handle(), "", digest[:], nil, &tpm2.SigScheme{
			Alg:  tpm2.AlgRSAPSS,
			Hash: tpm2.AlgSHA256,
		})
	} else if t.SignatureAlgorithm == x509.ECDSAWithSHA256 {

		tsig, err := tpm2.Sign(t.TpmDevice, t.Key.Handle(), "", digest[:], nil, &tpm2.SigScheme{
			Alg:  tpm2.AlgECDSA,
			Hash: tpm2.AlgSHA256,
		})

		if err != nil {
			fmt.Printf("Failed to sign: %v", err)
			return nil, fmt.Errorf("sign:  Failed to sign %v", err)
		}
		// dont' use asn1
		// sigStruct := struct{ R, S *big.Int }{tsig.ECC.R, tsig.ECC.S}
		// return asn1.Marshal(sigStruct), nil

		// https://github.com/golang-jwt/jwt/blob/main/ecdsa.go#L92
		epub := t.Key.PublicKey().(*ecdsa.PublicKey)
		curveBits := epub.Curve.Params().BitSize
		keyBytes := curveBits / 8
		if curveBits%8 > 0 {
			keyBytes += 1
		}
		out := make([]byte, 2*keyBytes)
		tsig.ECC.R.FillBytes(out[0:keyBytes])
		tsig.ECC.S.FillBytes(out[keyBytes:])
		return out, nil

	} else {
		return nil, errors.New("Unsupported signature type")
	}

	if err != nil {
		fmt.Printf("Failed to sign: %v", err)
		return []byte(""), fmt.Errorf("sign:  Failed to sign %v", err)
	}

	return signed.RSA.Signature, nil

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
