// Copyright 2020 Google LLC.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tpm

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
	"net/http"
	"sync"

	"github.com/hashicorp/vault/api"
)

const (
	refreshWindow = 60
)

var (
	x509Certificate    x509.Certificate
	publicKey          crypto.PublicKey
	clientCAs          *x509.CertPool
	clientAuth         *tls.ClientAuthType
	caPEM              string
	publicCert         string
	privatePEM         string
	signatureAlgorithm x509.SignatureAlgorithm
)

type Vault struct {
	crypto.Signer
	crypto.Decrypter

	ExtTLSConfig       *tls.Config
	SignatureAlgorithm x509.SignatureAlgorithm

	CertCN      string
	VaultToken  string
	VaultPath   string
	VaultCAcert string
	VaultAddr   string

	vaultTokenSecret *api.Secret

	refreshMutex sync.Mutex
}

func NewVaultCrypto(conf *Vault) (Vault, error) {

	var caCertPool *x509.CertPool
	caCertPool = x509.NewCertPool()
	if conf.VaultCAcert != "" {
		caCert, err := ioutil.ReadFile(conf.VaultCAcert)
		if err != nil {
			return Vault{}, fmt.Errorf("Unable to read root CA certificate for Vault Server: %v", err)
		}
		caCertPool.AppendCertsFromPEM(caCert)
	}

	config := &api.Config{
		Address: conf.VaultAddr,
		HttpClient: &http.Client{Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs: caCertPool,
			},
		}},
	}

	client, err := api.NewClient(config)
	if err != nil {
		return Vault{}, fmt.Errorf("Unable to initialize vault client: %v", err)
	}

	client.SetToken(conf.VaultToken)

	vaultTokenSecret, err := client.Auth().Token().LookupSelf()
	if err != nil {
		return Vault{}, fmt.Errorf("VaultToken: cannot lookup token details: %v", err)
	}

	timeLeft, err := vaultTokenSecret.TokenTTL()
	if err != nil {
		return Vault{}, fmt.Errorf("VaultToken: unable to lookup token details: %v", err)
	}
	isRenewable, err := vaultTokenSecret.TokenIsRenewable()
	if err != nil {
		return Vault{}, fmt.Errorf("VaultToken: unable to lookup TokenIsRenewable: %v", err)
	}

	if timeLeft.Seconds() < refreshWindow && !isRenewable {
		return Vault{}, fmt.Errorf("VaultToken expired not renewable: %v", err)
	}

	if timeLeft.Seconds() < refreshWindow {
		vaultTokenSecret, err = client.Auth().Token().RenewSelf(0)
		if err != nil {
			return Vault{}, fmt.Errorf("VaultToken unable to renew vault token: %v", err)
		}
	}

	data := map[string]interface{}{
		"common_name": conf.CertCN,
	}

	secret, err := client.Logical().Write(conf.VaultPath, data)
	if err != nil {
		return Vault{}, fmt.Errorf("VaultToken:  Unable to read resource at path [%s] error: %v", conf.VaultPath, err)
	}

	d := secret.Data
	publicCert = d["certificate"].(string)
	caPEM = d["issuing_ca"].(string)
	privatePEM = d["private_key"].(string)

	return *conf, nil
}

func (t Vault) Public() crypto.PublicKey {

	pubKeyBlock, _ := pem.Decode([]byte(publicCert))

	var cert *x509.Certificate
	cert, _ = x509.ParseCertificate(pubKeyBlock.Bytes)
	publicKey := cert.PublicKey.(*rsa.PublicKey)

	return publicKey
}

func (t Vault) Sign(_ io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	t.refreshMutex.Lock()
	defer t.refreshMutex.Unlock()

	hash := opts.HashFunc()
	if len(digest) != hash.Size() {
		return nil, fmt.Errorf("sal: Sign: Digest length doesn't match passed crypto algorithm")
	}

	block, _ := pem.Decode([]byte(privatePEM))
	if block == nil {
		return nil, fmt.Errorf("failed to parse PEM block containing the key")
	}
	priv, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("sal: Sign: Digest length doesn't match passed crypto algorithm")
	}

	var signature []byte
	// RSA-PSS: https://github.com/golang/go/issues/32425

	if t.SignatureAlgorithm == x509.SHA256WithRSAPSS {
		var ropts rsa.PSSOptions
		ropts.SaltLength = rsa.PSSSaltLengthEqualsHash

		signature, err = rsa.SignPSS(rand.Reader, priv, opts.HashFunc(), digest, &ropts)
		if err != nil {
			return nil, fmt.Errorf("failed to sign RSA-PSS %v", err)
		}
	} else {
		signature, err = rsa.SignPKCS1v15(rand.Reader, priv, opts.HashFunc(), digest)
		if err != nil {
			return nil, fmt.Errorf("failed to sign RSA-SignPKCS1v15 %v", err)
		}
		if err != nil {
			return nil, fmt.Errorf("failed to sign RSA-PSS %v", err)
		}
	}
	return signature, nil

}

func (t Vault) TLSCertificate() tls.Certificate {

	block, _ := pem.Decode([]byte(publicCert))
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

func (t Vault) TLSConfig() *tls.Config {

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
