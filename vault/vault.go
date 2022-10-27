// Copyright 2020 Google LLC.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tpm

import (
	"crypto"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"strings"
	"sync"

	"github.com/hashicorp/vault/api"
)

const (
	refreshWindow = 60
)

var (
	x509Certificate x509.Certificate
	publicKey       crypto.PublicKey
	publicCert      string
	client          *api.Client
)

type Vault struct {
	crypto.Signer
	crypto.Decrypter

	ExtTLSConfig       *tls.Config
	SignatureAlgorithm x509.SignatureAlgorithm
	PublicCertFile     string
	VaultToken         string
	KeyPath            string
	SignPath           string
	KeyVersion         int
	VerifyPath         string // not used
	VaultCAcert        string
	VaultAddr          string

	refreshMutex sync.Mutex
}

func NewVaultCrypto(conf *Vault) (Vault, error) {

	caCertPool := x509.NewCertPool()
	if conf.VaultCAcert != "" {
		caCert, err := ioutil.ReadFile(conf.VaultCAcert)
		if err != nil {
			return Vault{}, fmt.Errorf("unable to read root CA certificate for Vault Server: %v", err)
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

	if conf.KeyVersion == 0 {
		return Vault{}, errors.New("KeyVersion must be set")
	}

	if conf.VaultToken == "" {
		return Vault{}, errors.New("VaultToken must be set")
	}

	if conf.KeyPath == "" || conf.SignPath == "" {
		return Vault{}, errors.New("KeyPath and SignPath must be set")
	}

	var err error
	client, err = api.NewClient(config)
	if err != nil {
		return Vault{}, fmt.Errorf("unable to initialize vault client: %v", err)
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
		// todo, verify if the clienttoken is actually what we need
		client.SetToken(vaultTokenSecret.Auth.ClientToken)
	}

	secret, err := client.Logical().Read(conf.KeyPath)
	if err != nil {
		return Vault{}, fmt.Errorf("VaultToken:  Unable to read resource at path [%s] error: %v", conf.KeyPath, err)
	}

	d := secret.Data
	keys, ok := d["keys"].(map[string]interface{})
	if ok {
		firstKey, ok := keys[fmt.Sprintf("%d", conf.KeyVersion)].(map[string]interface{})
		if ok {
			pubPEM := firstKey["public_key"].(string)

			block, _ := pem.Decode([]byte(fmt.Sprintf("\n%s\n", pubPEM)))
			if block == nil {
				return Vault{}, fmt.Errorf("failed to parse PEM block containing the key ")
			}

			pub, err := x509.ParsePKIXPublicKey(block.Bytes)
			if err != nil {
				return Vault{}, err
			}
			publicKey, ok = pub.(crypto.PublicKey)
			if !ok {
				return Vault{}, fmt.Errorf("failed convert public key")
			}
		}
	}
	return *conf, nil
}

func (t Vault) Public() crypto.PublicKey {
	return publicKey
}

func (t Vault) Sign(_ io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	t.refreshMutex.Lock()
	defer t.refreshMutex.Unlock()

	b64Data := base64.StdEncoding.EncodeToString(digest)

	var signature []byte

	if t.SignatureAlgorithm == x509.SHA256WithRSAPSS {
		salt := "auto"

		ropts, ok := opts.(*rsa.PSSOptions)
		if ok {
			if ropts.SaltLength == rsa.PSSSaltLengthEqualsHash {
				//salt = "hash"
				// todo, i can't get this working so bail
				return nil, errors.New("PSSSaltLengthEqualsHash not supported")
			}
		}
		data := map[string]interface{}{
			"input":               b64Data,
			"signature_algorithm": "pss",
			"prehashed":           true,
			"hash_algorithm":      "sha2-256",
			"salt":                salt,
		}
		secret, err := client.Logical().Write(t.SignPath, data)
		if err != nil {
			return nil, fmt.Errorf("VaultToken:  Unable to  sign  %v", err)
		}

		d := secret.Data
		sig, ok := d["signature"].(string)
		if ok {
			signature, err = base64.StdEncoding.DecodeString(strings.TrimPrefix(sig, "vault:v1:"))
			if err != nil {
				return nil, fmt.Errorf("VaultToken:  Unable to  base64decode signature  %v", err)
			}
		} else {
			return nil, fmt.Errorf("VaultToken:  Error Signing")
		}
	} else {
		data := map[string]interface{}{
			"input":               b64Data,
			"signature_algorithm": "pkcs1v15",
			"prehashed":           true,
			"hash_algorithm":      "sha2-256",
		}
		secret, err := client.Logical().Write(t.SignPath, data)
		if err != nil {
			return nil, fmt.Errorf("VaultToken:  Unable to  sign  %v", err)
		}

		d := secret.Data
		sig, ok := d["signature"].(string)
		if ok {
			signature, err = base64.StdEncoding.DecodeString(strings.TrimPrefix(sig, "vault:v1:"))
			if err != nil {
				return nil, fmt.Errorf("VaultToken:  Unable to  base64decode signature  %v", err)
			}
		} else {
			return nil, fmt.Errorf("VaultToken:  Error Signing")
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

	if publicCert == "" {
		fmt.Errorf("publicCert variable must be set for TLS")
		return nil
	}
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
