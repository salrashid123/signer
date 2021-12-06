// Copyright 2020 Google LLC.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.package tpm
package pem

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"io/ioutil"
	"sync"
)

const ()

var (
	x509Certificate    x509.Certificate
	publicKey          crypto.PublicKey
	clientCAs          *x509.CertPool
	clientAuth         *tls.ClientAuthType
	signatureAlgorithm x509.SignatureAlgorithm
)

type PEM struct {
	crypto.Signer

	ExtTLSConfig *tls.Config

	PublicCertFile string
	PrivatePEMFile string

	privateKey *rsa.PrivateKey

	SignatureAlgorithm x509.SignatureAlgorithm
	refreshMutex       sync.Mutex
}

// Just to test crypto.Singer, crypto.Decrypt interfaces
// the following Decrypt and Sign functions uses ordinary private keys

func NewPEMCrypto(conf *PEM) (PEM, error) {

	if conf.SignatureAlgorithm == x509.UnknownSignatureAlgorithm {
		conf.SignatureAlgorithm = x509.SHA256WithRSA
	}
	if (conf.SignatureAlgorithm != x509.SHA256WithRSA) && (conf.SignatureAlgorithm != x509.SHA256WithRSAPSS) {
		return PEM{}, fmt.Errorf("signatureALgorithm must be either x509.SHA256WithRSA or x509.SHA256WithRSAPSS")
	}

	if conf.PrivatePEMFile == "" {
		return PEM{}, fmt.Errorf("privateKey cannot be empoty")
	}

	privatePEM, err := ioutil.ReadFile(conf.PrivatePEMFile)
	if err != nil {
		return PEM{}, fmt.Errorf("Unable to read keys %v", err)
	}
	block, _ := pem.Decode(privatePEM)
	if block == nil {
		return PEM{}, fmt.Errorf("failed to parse PEM block containing the key")
	}
	priv, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return PEM{}, err
	}
	conf.privateKey = priv

	if conf.ExtTLSConfig != nil {
		if len(conf.ExtTLSConfig.Certificates) > 0 {
			return PEM{}, fmt.Errorf("certificates value in ExtTLSConfig Ignored")
		}

		if len(conf.ExtTLSConfig.CipherSuites) > 0 {
			return PEM{}, fmt.Errorf("cipherSuites value in ExtTLSConfig Ignored")
		}
	}
	return *conf, nil
}

func (t PEM) Public() crypto.PublicKey {
	return t.privateKey.Public().(crypto.PublicKey)
}

func (t PEM) Sign(_ io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	t.refreshMutex.Lock()
	defer t.refreshMutex.Unlock()

	hash := opts.HashFunc()
	if len(digest) != hash.Size() {
		return nil, fmt.Errorf("sal: Sign: Digest length doesn't match passed crypto algorithm")
	}

	var signature []byte
	var err error
	// RSA-PSS: https://github.com/golang/go/issues/32425

	if t.SignatureAlgorithm == x509.SHA256WithRSAPSS {
		var ropts rsa.PSSOptions
		ropts.SaltLength = rsa.PSSSaltLengthEqualsHash

		signature, err = rsa.SignPSS(rand.Reader, t.privateKey, opts.HashFunc(), digest, &ropts)
		if err != nil {
			return nil, fmt.Errorf("failed to sign RSA-PSS %v", err)
		}
	} else {
		signature, err = rsa.SignPKCS1v15(rand.Reader, t.privateKey, opts.HashFunc(), digest)
		if err != nil {
			return nil, fmt.Errorf("failed to sign RSA-SignPKCS1v15 %v", err)
		}
		if err != nil {
			return nil, fmt.Errorf("failed to sign RSA-PSS %v", err)
		}
	}
	return signature, nil
}

func (t PEM) TLSCertificate() tls.Certificate {

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

func (t PEM) TLSConfig() *tls.Config {

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
