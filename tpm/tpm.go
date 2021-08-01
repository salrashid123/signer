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
	"log"
	"sync"

	"github.com/google/go-tpm-tools/client"
	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpmutil"
)

const ()

var (
	x509Certificate x509.Certificate
	publicKey       crypto.PublicKey
	clientCAs       *x509.CertPool
	clientAuth      *tls.ClientAuthType
	rwc             io.ReadWriteCloser

	unrestrictedKeyParams = tpm2.Public{
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
	crypto.Decrypter

	PublicCertFile string
	ExtTLSConfig   *tls.Config

	TpmHandleFile string
	TpmHandle     uint32
	TpmDevice     string
	refreshMutex  sync.Mutex
}

func NewTPMCrypto(conf *TPM) (TPM, error) {

	var err error
	rwc, err := tpm2.OpenTPM(conf.TpmDevice)
	if err != nil {
		return TPM{}, fmt.Errorf("google: Public: Unable to Open TPM: %v", err)
	}
	defer rwc.Close()

	if conf.TpmHandleFile != "" && conf.TpmHandle != 0 {
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

func (t TPM) TLSCertificate() tls.Certificate {

	if t.PublicCertFile == "" {
		log.Fatalf("Public X509 certificate not specified")
	}

	pubPEM, err := ioutil.ReadFile(t.PublicCertFile)
	if err != nil {
		log.Fatalf("Unable to read keys %v", err)
	}
	block, _ := pem.Decode([]byte(pubPEM))
	if block == nil {
		log.Fatalf("failed to parse PEM block containing the public key")
	}
	pub, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		log.Fatalf("failed to parse public key: " + err.Error())
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

		RootCAs:    t.ExtTLSConfig.RootCAs,
		ClientCAs:  t.ExtTLSConfig.ClientCAs,
		ClientAuth: t.ExtTLSConfig.ClientAuth,
		ServerName: t.ExtTLSConfig.ServerName,

		CipherSuites: []uint16{
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_RSA_WITH_AES_128_CBC_SHA256,
		},
		MaxVersion: tls.VersionTLS12,
	}
}

func (t TPM) Public() crypto.PublicKey {
	if publicKey == nil {
		t.refreshMutex.Lock()
		defer t.refreshMutex.Unlock()

		rwc, err := tpm2.OpenTPM(t.TpmDevice)
		if err != nil {
			return err
		}
		defer rwc.Close()

		var handle tpmutil.Handle
		defer tpm2.FlushContext(rwc, handle)
		if t.TpmHandleFile != "" {
			log.Printf("     ContextLoad (%s) ========", t.TpmHandleFile)
			pHBytes, err := ioutil.ReadFile(t.TpmHandleFile)
			if err != nil {
				log.Fatalf("google: Unable to Read Public data from TPM: %v", err)
			}
			handle, err = tpm2.ContextLoad(rwc, pHBytes)
			if err != nil {
				return nil
			}
		} else {
			handle = tpmutil.Handle(t.TpmHandle)
		}

		pub, _, _, err := tpm2.ReadPublic(rwc, handle)
		if err != nil {
			log.Fatalf("google: Unable to Read Public data from TPM: %v", err)
		}
		pubKey, err := pub.Key()
		if err != nil {
			log.Fatalf("google: Unable to Read Public key from TPM: %v", err)
		}
		publicKey = pubKey.(*rsa.PublicKey)
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
	k, err := client.NewCachedKey(rwc, tpm2.HandleEndorsement, unrestrictedKeyParams, kh)
	if err != nil {
		return []byte(""), fmt.Errorf("Couldnot load CachedKey: %v", err)
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

func (t TPM) Decrypt(rand io.Reader, msg []byte, opts crypto.DecrypterOpts) ([]byte, error) {
	t.refreshMutex.Lock()
	defer t.refreshMutex.Unlock()

	rwc, err := tpm2.OpenTPM(t.TpmDevice)
	if err != nil {
		return []byte(""), err
	}
	defer rwc.Close()

	var handle tpmutil.Handle
	defer tpm2.FlushContext(rwc, handle)
	if t.TpmHandleFile != "" {
		log.Printf("     ContextLoad (%s) ========", t.TpmHandleFile)
		pHBytes, err := ioutil.ReadFile(t.TpmHandleFile)
		if err != nil {
			return []byte(""), fmt.Errorf("     ContextLoad failed for importedKey: %v", err)
		}
		handle, err = tpm2.ContextLoad(rwc, pHBytes)
		if err != nil {
			return []byte(""), fmt.Errorf("     ContextLoad failed for importedKey: %v", err)
		}
	} else {
		handle = tpmutil.Handle(t.TpmHandle)
	}

	dec, err := tpm2.RSADecrypt(rwc, handle, "", msg, &tpm2.AsymScheme{
		Alg:  tpm2.AlgOAEP,
		Hash: tpm2.AlgSHA256,
	}, "")
	if err != nil {
		return nil, fmt.Errorf("google: Unable to Decrypt with TPM: %v", err)
	}
	return dec, nil
}

func (t TPM) Close() error {
	return rwc.Close()
}
