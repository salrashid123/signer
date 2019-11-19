package kms

import (
	"crypto"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"io"
	"log"
	"sync"

	"context"
	"fmt"
	"io/ioutil"

	"golang.org/x/oauth2/google"
	cloudkms "google.golang.org/api/cloudkms/v1"
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
	Certificates  []tls.Certificate
	RootCAs       *x509.CertPool
	ClientCAs     *x509.CertPool
	ClientAuth    tls.ClientAuthType

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
	return *conf, nil
}

func (t KMS) Public() crypto.PublicKey {
	if publicKey == nil {
		ctx := context.Background()
		parentName := fmt.Sprintf("projects/%s/locations/%s/keyRings/%s/cryptoKeys/%s/cryptoKeyVersions/%s", t.ProjectId, t.LocationId, t.KeyRing, t.Key, t.KeyVersion)

		kmsClient, err := google.DefaultClient(ctx, cloudkms.CloudPlatformScope)
		if err != nil {
			log.Fatal(err)
		}
		kmsService, err := cloudkms.New(kmsClient)
		if err != nil {
			log.Fatal(err)
		}

		dresp, err := kmsService.Projects.Locations.KeyRings.CryptoKeys.CryptoKeyVersions.GetPublicKey(parentName).Do()
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
	rootCAs = t.RootCAs
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
		RootCAs:      t.RootCAs,
		ClientCAs:    t.ClientCAs,
		ClientAuth:   t.ClientAuth,

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

	kmsClient, err := google.DefaultClient(ctx, cloudkms.CloudPlatformScope)
	if err != nil {
		log.Fatal(err)
	}
	kmsService, err := cloudkms.New(kmsClient)
	if err != nil {
		log.Fatal(err)
	}

	s := base64.StdEncoding.EncodeToString(digest)
	drq := &cloudkms.AsymmetricSignRequest{
		Digest: &cloudkms.Digest{
			Sha256: s,
		},
	}
	dresp, err := kmsService.Projects.Locations.KeyRings.CryptoKeys.CryptoKeyVersions.AsymmetricSign(parentName, drq).Do()
	if err != nil {
		log.Fatal(err)
	}

	signedResp, err := base64.StdEncoding.DecodeString(dresp.Signature)
	if err != nil {
		log.Fatalln(err)
	}
	return []byte(signedResp), nil

}

func (t KMS) Decrypt(rand io.Reader, msg []byte, opts crypto.DecrypterOpts) ([]byte, error) {
	refreshMutex.Lock()
	defer refreshMutex.Unlock()

	ctx := context.Background()
	parentName := fmt.Sprintf("projects/%s/locations/%s/keyRings/%s/cryptoKeys/%s/cryptoKeyVersions/%s", t.ProjectId, t.LocationId, t.KeyRing, t.Key, t.KeyVersion)

	kmsClient, err := google.DefaultClient(ctx, cloudkms.CloudPlatformScope)
	if err != nil {
		log.Fatal(err)
	}
	kmsService, err := cloudkms.New(kmsClient)
	if err != nil {
		log.Fatal(err)
	}

	s := base64.StdEncoding.EncodeToString(msg)
	drq := &cloudkms.AsymmetricDecryptRequest{
		Ciphertext: s,
	}
	dresp, err := kmsService.Projects.Locations.KeyRings.CryptoKeys.CryptoKeyVersions.AsymmetricDecrypt(parentName, drq).Do()
	if err != nil {
		log.Fatal(err)
	}

	plainText, err := base64.StdEncoding.DecodeString(dresp.Plaintext)
	if err != nil {
		log.Fatalln(err)
	}

	return []byte(plainText), nil
}
