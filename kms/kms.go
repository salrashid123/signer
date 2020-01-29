// Copyright 2020 Google LLC.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package kms

import (
	"crypto"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"io"
	"log"
	"sync"

	"context"
	"fmt"
	"io/ioutil"

	cloudkms "cloud.google.com/go/kms/apiv1"
	kmspb "google.golang.org/genproto/googleapis/cloud/kms/v1"
)

const ()

var (
	refreshMutex    = &sync.Mutex{}
	x509Certificate x509.Certificate
	publicKey       crypto.PublicKey
	rootCAs         *x509.CertPool
	clientCAs       *x509.CertPool
	clientAuth      *tls.ClientAuthType
)

type KMS struct {
	crypto.Signer    // https://golang.org/pkg/crypto/#Signer
	crypto.Decrypter // https://golang.org/pkg/crypto/#Decrypter

	PublicKeyFile string
	ExtTLSConfig  *tls.Config

	ProjectId  string
	LocationId string
	KeyRing    string
	Key        string
	KeyVersion string
}

func NewKMSCrypto(conf *KMS) (KMS, error) {
	if conf.ProjectId == "" {
		return KMS{}, fmt.Errorf("ProjectID cannot be null")
	}
	if conf.ExtTLSConfig != nil {
		if len(conf.ExtTLSConfig.Certificates) > 0 {
			return KMS{}, fmt.Errorf("Certificates value in ExtTLSConfig Ignored")
		}

		if len(conf.ExtTLSConfig.CipherSuites) > 0 {
			return KMS{}, fmt.Errorf("CipherSuites value in ExtTLSConfig Ignored")
		}
	}
	return *conf, nil
}

func (t KMS) Public() crypto.PublicKey {
	if publicKey == nil {
		ctx := context.Background()
		parentName := fmt.Sprintf("projects/%s/locations/%s/keyRings/%s/cryptoKeys/%s/cryptoKeyVersions/%s", t.ProjectId, t.LocationId, t.KeyRing, t.Key, t.KeyVersion)

		kmsClient, err := cloudkms.NewKeyManagementClient(ctx)
		if err != nil {
			log.Fatal(err)
		}

		dresp, err := kmsClient.GetPublicKey(ctx, &kmspb.GetPublicKeyRequest{Name: parentName})
		if err != nil {
			log.Fatal(err)
		}
		pubKeyBlock, _ := pem.Decode([]byte(dresp.Pem))

		pub, err := x509.ParsePKIXPublicKey(pubKeyBlock.Bytes)
		if err != nil {
			log.Fatalf("failed to parse public key: " + err.Error())
		}
		publicKey = pub.(*rsa.PublicKey)
	}

	return publicKey
}

func (t KMS) TLSCertificate() tls.Certificate {

	if t.PublicKeyFile == "" {
		log.Fatalf("Public X509 certificate not specified")
	}

	pubPEM, err := ioutil.ReadFile(t.PublicKeyFile)
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

func (t KMS) TLSConfig() *tls.Config {
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

func (t KMS) Sign(_ io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	refreshMutex.Lock()
	defer refreshMutex.Unlock()

	ctx := context.Background()
	parentName := fmt.Sprintf("projects/%s/locations/%s/keyRings/%s/cryptoKeys/%s/cryptoKeyVersions/%s", t.ProjectId, t.LocationId, t.KeyRing, t.Key, t.KeyVersion)

	kmsClient, err := cloudkms.NewKeyManagementClient(ctx)
	if err != nil {
		log.Fatal(err)
	}

	req := &kmspb.AsymmetricSignRequest{
		Name: parentName,
		Digest: &kmspb.Digest{
			Digest: &kmspb.Digest_Sha256{
				Sha256: digest,
			},
		},
	}
	dresp, err := kmsClient.AsymmetricSign(ctx, req)

	return dresp.Signature, nil

}

func (t KMS) Decrypt(rand io.Reader, msg []byte, opts crypto.DecrypterOpts) ([]byte, error) {
	refreshMutex.Lock()
	defer refreshMutex.Unlock()

	ctx := context.Background()
	parentName := fmt.Sprintf("projects/%s/locations/%s/keyRings/%s/cryptoKeys/%s/cryptoKeyVersions/%s", t.ProjectId, t.LocationId, t.KeyRing, t.Key, t.KeyVersion)

	kmsClient, err := cloudkms.NewKeyManagementClient(ctx)
	if err != nil {
		log.Fatal(err)
	}

	dresp, err := kmsClient.AsymmetricDecrypt(ctx, &kmspb.AsymmetricDecryptRequest{
		Name:       parentName,
		Ciphertext: msg,
	})
	if err != nil {
		log.Fatal(err)
	}

	return dresp.Plaintext, nil
}
