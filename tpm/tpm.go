// Copyright 2020 Google LLC.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tpm

import (
	"crypto"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"io/ioutil"
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
				Alg:  tpm2.AlgRSASSA,
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

	if conf.TpmHandleFile != "" && conf.TpmHandle != 0 {
		return TPM{}, fmt.Errorf("At most one of TpmHandle or TpmHandleFile must be specified")
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
		k, err := client.NewCachedKey(rwc, tpm2.HandleEndorsement, unrestrictedKeyParams, kh)
		if err != nil {
			fmt.Printf(": Public: error loading CachedKey: %v", err)
			return nil
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
	tpm2.FlushContext(rwc, handle)
	return dec, nil
}

func (t TPM) Close() error {
	return rwc.Close()
}
