// Copyright 2020 Google LLC.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.package tpm
package pem

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"sync"
)

const ()

var (
	x509Certificate x509.Certificate
	publicKey       crypto.PublicKey
	clientCAs       *x509.CertPool
	clientAuth      *tls.ClientAuthType
	publicKeyFile   string
	privateKeyFile  string
)

type PEM struct {
	crypto.Signer
	crypto.Decrypter

	ExtTLSConfig *tls.Config

	PublicCertFile string
	PublicPEMFile  string
	PrivatePEMFile string

	refreshMutex sync.Mutex
}

// Just to test crypto.Singer, crypto.Decrypt interfaces
// the following Decrypt and Sign functions uses ordinary private keys

func NewPEMCrypto(conf *PEM) (PEM, error) {
	publicKeyFile = conf.PublicPEMFile
	privateKeyFile = conf.PrivatePEMFile

	if conf.ExtTLSConfig != nil {
		if len(conf.ExtTLSConfig.Certificates) > 0 {
			return PEM{}, fmt.Errorf("Certificates value in ExtTLSConfig Ignored")
		}

		if len(conf.ExtTLSConfig.CipherSuites) > 0 {
			return PEM{}, fmt.Errorf("CipherSuites value in ExtTLSConfig Ignored")
		}
	}
	return *conf, nil
}

func (t PEM) Public() crypto.PublicKey {

	if t.PublicCertFile != "" {
		if publicKey == nil {
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

			publicKey = pub.PublicKey
		}
	} else {

		if publicKey == nil {
			publicPEM, err := ioutil.ReadFile(publicKeyFile)
			if err != nil {
				log.Fatalf("Unable to read keys %v", err)
			}
			pubKeyBlock, _ := pem.Decode((publicPEM))

			pub, err := x509.ParsePKIXPublicKey(pubKeyBlock.Bytes)
			if err != nil {
				log.Fatalf("failed to parse public key: " + err.Error())
			}
			publicKey = pub.(*rsa.PublicKey)
		}
	}

	return publicKey
}

func (t PEM) Sign(_ io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	t.refreshMutex.Lock()
	defer t.refreshMutex.Unlock()

	hash := opts.HashFunc()
	if len(digest) != hash.Size() {
		return nil, fmt.Errorf("sal: Sign: Digest length doesn't match passed crypto algorithm")
	}

	privatePEM, err := ioutil.ReadFile(privateKeyFile)
	if err != nil {
		return nil, fmt.Errorf("Unable to read keys %v", err)
	}
	block, _ := pem.Decode(privatePEM)
	if block == nil {
		return nil, fmt.Errorf("failed to parse PEM block containing the key")
	}
	priv, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	// RSA-PSS: https://github.com/golang/go/issues/32425
	var ropts rsa.PSSOptions
	ropts.SaltLength = rsa.PSSSaltLengthEqualsHash

	signature, err := rsa.SignPSS(rand.Reader, priv, opts.HashFunc(), digest, &ropts)
	if err != nil {
		return nil, fmt.Errorf("failed to sign RSA-PSS %v", err)
	}
	return signature, nil
}

func (t PEM) Decrypt(rand io.Reader, msg []byte, opts crypto.DecrypterOpts) ([]byte, error) {
	t.refreshMutex.Lock()
	defer t.refreshMutex.Unlock()

	privatePEM, err := ioutil.ReadFile(privateKeyFile)
	if err != nil {
		return nil, fmt.Errorf("Unable to read keys %v", err)
	}
	block, _ := pem.Decode(privatePEM)
	if block == nil {
		return nil, fmt.Errorf("failed to parse PEM block containing the key")
	}
	priv, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	hash := sha256.New()
	decryptedData, decryptErr := rsa.DecryptOAEP(hash, rand, priv, msg, nil)
	if decryptErr != nil {
		return nil, fmt.Errorf("Decrypt data error")
	}
	return decryptedData, nil
}

func (t PEM) TLSCertificate() tls.Certificate {

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

func (t PEM) TLSConfig() *tls.Config {

	return &tls.Config{
		Certificates: []tls.Certificate{t.TLSCertificate()},
		RootCAs:      t.ExtTLSConfig.RootCAs,
		ClientCAs:    t.ExtTLSConfig.ClientCAs,
		ClientAuth:   t.ExtTLSConfig.ClientAuth,
		ServerName:   t.ExtTLSConfig.ServerName,

		CipherSuites: []uint16{
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_RSA_WITH_AES_128_CBC_SHA256,
		},
		MaxVersion: tls.VersionTLS12,
	}
}
