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
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"sync"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpmutil"
)

const ()

var (
	x509Certificate x509.Certificate
	publicKey       crypto.PublicKey

	handleNames = map[string][]tpm2.HandleType{
		"all":       []tpm2.HandleType{tpm2.HandleTypeLoadedSession, tpm2.HandleTypeSavedSession, tpm2.HandleTypeTransient},
		"loaded":    []tpm2.HandleType{tpm2.HandleTypeLoadedSession},
		"saved":     []tpm2.HandleType{tpm2.HandleTypeSavedSession},
		"transient": []tpm2.HandleType{tpm2.HandleTypeTransient},
	}
)

type TPM struct {
	crypto.Signer

	TpmHandleFile      string
	TpmHandle          uint32
	TpmDevice          string
	SignatureAlgorithm x509.SignatureAlgorithm
	refreshMutex       sync.Mutex
	PublicCertFile     string
	ExtTLSConfig       *tls.Config
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

	// for _, handleType := range handleNames["all"] {
	// 	handles, err := client.Handles(rwc, handleType)
	// 	if err != nil {
	// 		return TPM{}, fmt.Errorf("error getting handles")
	// 	}
	// 	for _, handle := range handles {
	// 		if err = tpm2.FlushContext(rwc, handle); err != nil {
	// 			return TPM{}, fmt.Errorf("error flushing 0x%x: %v", handle, err)
	// 		}
	// 	}
	// }

	if conf.TpmHandleFile == "" && conf.TpmHandle == 0 {
		return TPM{}, fmt.Errorf("at most one of TpmHandle or TpmHandleFile must be specified")
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
	if publicKey == nil {
		t.refreshMutex.Lock()
		defer t.refreshMutex.Unlock()

		var err error
		var kh tpmutil.Handle
		rwc, err := tpm2.OpenTPM(t.TpmDevice)
		if err != nil {
			fmt.Printf(": Public: Unable to Open TPM: %v\n", err)
			return nil
		}
		defer tpm2.FlushContext(rwc, kh)
		defer rwc.Close()

		if t.TpmHandleFile != "" {
			khBytes, err := ioutil.ReadFile(t.TpmHandleFile)
			if err != nil {
				fmt.Printf("public: ContextLoad read file for kh: %v\n", err)
				return nil
			}
			kh, err = tpm2.ContextLoad(rwc, khBytes)
			if err != nil {
				fmt.Printf("public: ContextLoad read file for kh: %v\n", err)
				return nil
			}
		} else if t.TpmHandle != 0 {
			kh = tpmutil.Handle(t.TpmHandle)
		} else {
			fmt.Println("public: both tpmHandlefile and tpmhandle are null")
			return errors.New("public: both tpmHandlefile and tpmhandle are null")
		}

		pub, _, _, err := tpm2.ReadPublic(rwc, kh)
		if err != nil {
			fmt.Printf("google: Unable to Read Public data from TPM: %v", err)
			return errors.New(fmt.Sprintf("fmt: Unable to Read Public data from TPM: %v", err))
		}
		tpm2.FlushContext(rwc, kh)

		pubKey, err := pub.Key()
		if err != nil {
			fmt.Printf("google: Unable to Read Public data from TPM: %v", err)
			return errors.New(fmt.Sprintf("fmt: Unable to Read Public data from TPM: %v", err))
		}
		publicKey = pubKey.(*rsa.PublicKey)
	}
	return publicKey
}

func (t TPM) Sign(rr io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	t.refreshMutex.Lock()
	defer t.refreshMutex.Unlock()

	var err error
	var kh tpmutil.Handle
	rwc, err := tpm2.OpenTPM(t.TpmDevice)
	if err != nil {
		return []byte(""), fmt.Errorf("google: Public: Unable to Open TPM: %v", err)
	}
	defer tpm2.FlushContext(rwc, kh)
	defer rwc.Close()

	if t.TpmHandleFile != "" {
		khBytes, err := ioutil.ReadFile(t.TpmHandleFile)
		if err != nil {
			fmt.Printf("sign: ContextLoad read file for kh: %v\n", err)
			return []byte(""), fmt.Errorf(" Public: ContextLoad read file for kh: %v", err)
		}
		kh, err = tpm2.ContextLoad(rwc, khBytes)
		if err != nil {
			fmt.Printf("sign: ContextLoad read file for kh: %v\n", err)
			return []byte(""), fmt.Errorf("Public: ContextLoad read file for kh:: %v", err)
		}
	} else if t.TpmHandle != 0 {
		kh = tpmutil.Handle(t.TpmHandle)
	}
	var signed *tpm2.Signature

	if t.SignatureAlgorithm == x509.SHA256WithRSA {
		signed, err = tpm2.Sign(rwc, kh, "", digest[:], nil, &tpm2.SigScheme{
			Alg:  tpm2.AlgRSASSA,
			Hash: tpm2.AlgSHA256,
		})
	} else {
		signed, err = tpm2.Sign(rwc, kh, "", digest[:], nil, &tpm2.SigScheme{
			Alg:  tpm2.AlgRSAPSS,
			Hash: tpm2.AlgSHA256,
		})
	}
	tpm2.FlushContext(rwc, kh)
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
