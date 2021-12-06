// Copyright 2020 Google LLC.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tpm

import (
	"crypto"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"io/ioutil"
	"sync"

	"github.com/google/go-tpm-tools/client"
	"github.com/google/go-tpm/tpm2"
)

const ()

var (
	x509Certificate x509.Certificate
	publicKey       crypto.PublicKey
	clientCAs       *x509.CertPool
	clientAuth      *tls.ClientAuthType
	rwc             io.ReadWriteCloser

	unrestrictedKeyParamsRSASSA = tpm2.Public{
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

	unrestrictedKeyParamsPSS = tpm2.Public{
		Type:    tpm2.AlgRSA,
		NameAlg: tpm2.AlgSHA256,
		Attributes: tpm2.FlagFixedTPM | tpm2.FlagFixedParent | tpm2.FlagSensitiveDataOrigin |
			tpm2.FlagUserWithAuth | tpm2.FlagSign,
		AuthPolicy: []byte{},
		RSAParameters: &tpm2.RSAParams{
			Sign: &tpm2.SigScheme{
				Alg:  tpm2.AlgRSAPSS,
				Hash: tpm2.AlgSHA256,
			},
			KeyBits: 2048,
		},
	}
)

type TPM struct {
	crypto.Signer

	TpmHandleFile      string
	TpmHandle          uint32
	TpmDevice          string
	SignatureAlgorithm x509.SignatureAlgorithm
	refreshMutex       sync.Mutex

	PublicCertFile string
	ExtTLSConfig   *tls.Config
}

func NewTPMCrypto(conf *TPM) (TPM, error) {

	if conf.SignatureAlgorithm == x509.UnknownSignatureAlgorithm {
		conf.SignatureAlgorithm = x509.SHA256WithRSA
	}
	if (conf.SignatureAlgorithm != x509.SHA256WithRSA) && (conf.SignatureAlgorithm != x509.SHA256WithRSAPSS) {
		return TPM{}, fmt.Errorf("signatureALgorithm must be either x509.SHA256WithRSA or x509.SHA256WithRSAPSS")
	}

	var err error
	rwc, err := tpm2.OpenTPM(conf.TpmDevice)
	if err != nil {
		return TPM{}, fmt.Errorf("google: Public: Unable to Open TPM: %v", err)
	}
	defer rwc.Close()

	if conf.TpmHandleFile == "" && conf.TpmHandle != 0 {
		return TPM{}, fmt.Errorf("At most one of TpmHandle or TpmHandleFile must be specified")
	}
	if conf.ExtTLSConfig != nil {
		if len(conf.ExtTLSConfig.Certificates) > 0 {
			return TPM{}, fmt.Errorf("Certificates value in ExtTLSConfig Ignored")
		}

		if len(conf.ExtTLSConfig.CipherSuites) > 0 {
			return TPM{}, fmt.Errorf("CipherSuites value in ExtTLSConfig Ignored")
		}
	}
	return *conf, nil
}

func (t TPM) Public() crypto.PublicKey {
	if publicKey == nil {
		t.refreshMutex.Lock()
		defer t.refreshMutex.Unlock()

		var err error
		rwc, err := tpm2.OpenTPM(t.TpmDevice)
		if err != nil {
			fmt.Printf(": Public: Unable to Open TPM: %v\n", err)
			return nil
		}
		defer rwc.Close()

		khBytes, err := ioutil.ReadFile(t.TpmHandleFile)
		if err != nil {
			fmt.Printf(": Public: ContextLoad read file for kh: %v", err)
			return nil
		}
		kh, err := tpm2.ContextLoad(rwc, khBytes)
		if err != nil {
			fmt.Printf(": Public: ContextLoad read file for kh: %v", err)
			return nil
		}
		defer tpm2.FlushContext(rwc, kh)
		var k *client.Key
		if t.SignatureAlgorithm == x509.SHA256WithRSA {
			k, err = client.NewCachedKey(rwc, tpm2.HandleEndorsement, unrestrictedKeyParamsRSASSA, kh)
			if err != nil {
				fmt.Printf(": Public: error loading CachedKey: %v", err)
				return nil
			}
		} else {
			k, err = client.NewCachedKey(rwc, tpm2.HandleEndorsement, unrestrictedKeyParamsPSS, kh)
			if err != nil {
				fmt.Printf(": Public: error loading CachedKey: %v", err)
				return nil
			}
		}

		s, err := k.GetSigner()
		if err != nil {
			fmt.Printf(": Public: Error getting signer: %v", err)
			return nil
		}
		publicKey = s.Public()
	}
	return publicKey
}

func (t TPM) Sign(rr io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	t.refreshMutex.Lock()
	defer t.refreshMutex.Unlock()

	var err error
	rwc, err := tpm2.OpenTPM(t.TpmDevice)
	if err != nil {
		return []byte(""), fmt.Errorf("google: Public: Unable to Open TPM: %v", err)
	}
	defer rwc.Close()

	khBytes, err := ioutil.ReadFile(t.TpmHandleFile)
	if err != nil {
		return []byte(""), fmt.Errorf("ContextLoad read file for kh: %v", err)
	}
	kh, err := tpm2.ContextLoad(rwc, khBytes)
	if err != nil {
		return []byte(""), fmt.Errorf("ContextLoad failed for kh: %v", err)
	}
	defer tpm2.FlushContext(rwc, kh)
	var k *client.Key
	if t.SignatureAlgorithm == x509.SHA256WithRSA {
		k, err = client.NewCachedKey(rwc, tpm2.HandleEndorsement, unrestrictedKeyParamsRSASSA, kh)
		if err != nil {
			return []byte(""), fmt.Errorf(": Public: error loading CachedKey: %v", err)
		}
	} else {
		k, err = client.NewCachedKey(rwc, tpm2.HandleEndorsement, unrestrictedKeyParamsPSS, kh)
		if err != nil {
			return []byte(""), fmt.Errorf(": Public: error loading CachedKey: %v", err)
		}
	}

	s, err := k.GetSigner()
	if err != nil {
		return []byte(""), fmt.Errorf("Couldnot get Signer: %v", err)
	}

	if _, ok := opts.(*rsa.PSSOptions); ok {
		opts = &rsa.PSSOptions{
			Hash:       crypto.SHA256,
			SaltLength: rsa.PSSSaltLengthAuto,
		}
	}
	return s.Sign(rr, digest, opts)

}

func (t TPM) TLSCertificate() tls.Certificate {

	if t.PublicCertFile == "" {
		fmt.Printf("Public X509 certificate not specified")
		return tls.Certificate{}
	}

	pubPEM, err := ioutil.ReadFile(t.PublicCertFile)
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

	x509Certificate = *pub
	var privKey crypto.PrivateKey = t
	return tls.Certificate{
		PrivateKey:  privKey,
		Leaf:        &x509Certificate,
		Certificate: [][]byte{x509Certificate.Raw},
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

func (t TPM) Close() error {
	return rwc.Close()
}
