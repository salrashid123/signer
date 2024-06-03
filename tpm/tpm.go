// Copyright 2020 Google LLC.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Creates a crypto.Signer() for TPM based credentials
//   Support RSA, ECC and keys with policiyPCR
// Also fulfils TLSCertificate() interface for use with TLS

package tpm

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"os"
	"sync"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
)

const ()

var ()

// Configures and manages Singer configuration
//

type TPM struct {
	crypto.Signer

	AuthHandle *tpm2.AuthHandle   // load a key from handle
	TpmDevice  io.ReadWriteCloser // TPM read closer

	EncryptionHandle tpm2.TPMHandle   // (optional) handle to use for transit encryption
	EncryptionPub    *tpm2.TPMTPublic // (optional) public key to use for transit encryption

	ECCRawOutput   bool // for ECC keys, output raw signatures. If false, signature is ans1 formatted
	refreshMutex   sync.Mutex
	PublicCertFile string // a provided public x509 certificate for the signer

	x509Certificate *x509.Certificate
	publicKey       crypto.PublicKey
	tpmPublic       tpm2.TPMTPublic
}

// Configure a new TPM crypto.Signer

func NewTPMCrypto(conf *TPM) (TPM, error) {

	if conf.AuthHandle == nil || conf.TpmDevice == nil {
		return TPM{}, fmt.Errorf("salrashid123/x/oauth2/google: AuthHandle and TpmDevice must be specified")
	}

	rwr := transport.FromReadWriter(conf.TpmDevice)

	pub, err := tpm2.ReadPublic{
		ObjectHandle: conf.AuthHandle.Handle,
	}.Execute(rwr)
	if err != nil {
		return TPM{}, fmt.Errorf("google: Unable to Read Public data from TPM: %v", err)
	}

	pc, err := pub.OutPublic.Contents()
	if err != nil {
		return TPM{}, fmt.Errorf("google: Unable to Read Public content TPM: %v", err)
	}
	conf.tpmPublic = *pc
	if pc.Type == tpm2.TPMAlgRSA {
		rsaDetail, err := pc.Parameters.RSADetail()
		if err != nil {
			return TPM{}, fmt.Errorf("google: Unable to Read Public rsa parameters TPM: %v", err)
		}

		rsaUnique, err := pc.Unique.RSA()
		if err != nil {
			return TPM{}, fmt.Errorf("google: Unable to Read Public rsa unique TPM: %v", err)
		}
		rsaPub, err := tpm2.RSAPub(rsaDetail, rsaUnique)
		if err != nil {
			return TPM{}, fmt.Errorf("google: Unable to create RSAPublic TPM: %v", err)
		}

		conf.publicKey = rsaPub
	} else if pc.Type == tpm2.TPMAlgECC {
		ecDetail, err := pc.Parameters.ECCDetail()
		if err != nil {
			return TPM{}, fmt.Errorf("google: Unable to Read Public ec parameters TPM: %v", err)
		}
		crv, err := ecDetail.CurveID.Curve()
		if err != nil {
			return TPM{}, fmt.Errorf("google: Unable to Read Public ec curve TPM: %v", err)
		}
		eccUnique, err := pc.Unique.ECC()
		if err != nil {
			return TPM{}, fmt.Errorf("google: Unable to Read Public ec unique TPM: %v", err)
		}
		conf.publicKey = &ecdsa.PublicKey{
			Curve: crv,
			X:     big.NewInt(0).SetBytes(eccUnique.X.Buffer),
			Y:     big.NewInt(0).SetBytes(eccUnique.Y.Buffer),
		}
	} else {
		return TPM{}, fmt.Errorf("google: Unsupported key type: %v", pc.Type)
	}

	return *conf, nil
}

func (t TPM) Public() crypto.PublicKey {
	return t.publicKey
}

func (t TPM) Sign(rr io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	t.refreshMutex.Lock()
	defer t.refreshMutex.Unlock()

	rwr := transport.FromReadWriter(t.TpmDevice)

	var sess tpm2.Session

	if t.EncryptionHandle != 0 && t.EncryptionPub != nil {
		sess = tpm2.HMAC(tpm2.TPMAlgSHA256, 16, tpm2.AESEncryption(128, tpm2.EncryptIn), tpm2.Salted(t.EncryptionHandle, *t.EncryptionPub))
	} else {
		sess = tpm2.HMAC(tpm2.TPMAlgSHA256, 16, tpm2.AESEncryption(128, tpm2.EncryptIn))
	}

	var algid tpm2.TPMIAlgHash

	if opts == nil {
		algid = tpm2.TPMAlgSHA256
	} else {
		if opts.HashFunc() == crypto.SHA256 {
			algid = tpm2.TPMAlgSHA256
		} else if opts.HashFunc() == crypto.SHA384 {
			algid = tpm2.TPMAlgSHA384
		} else if opts.HashFunc() == crypto.SHA512 {
			algid = tpm2.TPMAlgSHA512
		} else {
			return nil, fmt.Errorf("tpmjwt: unknown hash function %v", opts.HashFunc())
		}
	}

	var tsig []byte
	switch t.publicKey.(type) {
	case *rsa.PublicKey:
		rd, err := t.tpmPublic.Parameters.RSADetail()
		if err != nil {
			return nil, fmt.Errorf("tpmjwt: can't error getting rsa details %v", err)
		}
		rspSign, err := tpm2.Sign{
			KeyHandle: *t.AuthHandle,
			Digest: tpm2.TPM2BDigest{
				Buffer: digest[:],
			},
			InScheme: tpm2.TPMTSigScheme{
				Scheme: rd.Scheme.Scheme,
				Details: tpm2.NewTPMUSigScheme(rd.Scheme.Scheme, &tpm2.TPMSSchemeHash{
					HashAlg: algid,
				}),
			},
			Validation: tpm2.TPMTTKHashCheck{
				Tag: tpm2.TPMSTHashCheck,
			},
		}.Execute(rwr, sess)
		if err != nil {
			return nil, fmt.Errorf("tpmjwt: can't Sign: %v", err)
		}

		var rsig *tpm2.TPMSSignatureRSA
		if rspSign.Signature.SigAlg == tpm2.TPMAlgRSASSA {
			rsig, err = rspSign.Signature.Signature.RSASSA()
			if err != nil {
				return nil, fmt.Errorf("tpmjwt: error getting rsa ssa signature: %v", err)
			}
		} else if rspSign.Signature.SigAlg == tpm2.TPMAlgRSAPSS {
			rsig, err = rspSign.Signature.Signature.RSAPSS()
			if err != nil {
				return nil, fmt.Errorf("tpmjwt: error getting rsa pss signature: %v", err)
			}
		} else {
			return nil, fmt.Errorf("tpmjwt: unsupported signature algorithm't Sign: %v", err)
		}

		tsig = rsig.Sig.Buffer
	case *ecdsa.PublicKey:
		rd, err := t.tpmPublic.Parameters.ECCDetail()
		if err != nil {
			return nil, fmt.Errorf("tpmjwt: can't error getting rsa details %v", err)
		}
		rspSign, err := tpm2.Sign{
			KeyHandle: t.AuthHandle,
			Digest: tpm2.TPM2BDigest{
				Buffer: digest[:],
			},
			InScheme: tpm2.TPMTSigScheme{
				Scheme: rd.Scheme.Scheme,
				Details: tpm2.NewTPMUSigScheme(rd.Scheme.Scheme, &tpm2.TPMSSchemeHash{
					HashAlg: algid,
				}),
			},
			Validation: tpm2.TPMTTKHashCheck{
				Tag: tpm2.TPMSTHashCheck,
			},
		}.Execute(rwr, sess)
		if err != nil {
			return nil, fmt.Errorf("tpmjwt: can't Sign: %v", err)
		}

		rsig, err := rspSign.Signature.Signature.ECDSA()
		if err != nil {
			return nil, fmt.Errorf("tpmjwt: error getting ecc signature: %v", err)
		}
		if t.ECCRawOutput {
			tsig = append(rsig.SignatureR.Buffer, rsig.SignatureS.Buffer...)
		} else {
			r := big.NewInt(0).SetBytes(rsig.SignatureR.Buffer)
			s := big.NewInt(0).SetBytes(rsig.SignatureS.Buffer)
			sigStruct := struct{ R, S *big.Int }{r, s}
			return asn1.Marshal(sigStruct)
		}
	}
	return tsig, nil
}

func (t TPM) TLSCertificate() (tls.Certificate, error) {

	if t.PublicCertFile == "" {
		return tls.Certificate{}, fmt.Errorf("Public X509 certificate not specified")
	}

	if t.x509Certificate == nil {
		pubPEM, err := os.ReadFile(t.PublicCertFile)
		if err != nil {
			return tls.Certificate{}, fmt.Errorf("unable to read public certificate file %v", err)
		}
		block, _ := pem.Decode([]byte(pubPEM))
		if block == nil {
			return tls.Certificate{}, fmt.Errorf("failed to parse PEM block containing the public key")
		}
		pub, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return tls.Certificate{}, fmt.Errorf("unable to read public certificate file %v", err)
		}
		t.x509Certificate = pub
	}

	var privKey crypto.PrivateKey = t
	return tls.Certificate{
		PrivateKey:  privKey,
		Leaf:        t.x509Certificate,
		Certificate: [][]byte{t.x509Certificate.Raw},
	}, nil
}
