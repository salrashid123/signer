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

// Configures and manages Singer configuration
//

type TPM struct {
	crypto.Signer

	ECCRawOutput bool // for ECC keys, output raw signatures. If false, signature is ans1 formatted
	refreshMutex sync.Mutex

	// PublicCertFile path to the x509 certificate for the signer.  Used for TLS
	//
	// Deprecated: use X509Certificate instead
	PublicCertFile string // a provided public x509 certificate for the signer

	// X509Certificate raw x509 certificate for the signer. Used for TLS
	X509Certificate *x509.Certificate // public x509 certificate for the signer
	publicKey       crypto.PublicKey
	tpmPublic       tpm2.TPMTPublic

	//NamedHandle      *tpm2.NamedHandle  // the name handle to the key to use
	Handle           tpm2.TPMHandle // the name handle to the key to use
	name             tpm2.TPM2BName
	AuthSession      Session            // If the key needs a session, supply `Session` from this repo
	TpmDevice        io.ReadWriteCloser // TPM read closer
	EncryptionHandle tpm2.TPMHandle     // (optional) handle to use for transit encryption
}

// Configure a new TPM crypto.Signer

func NewTPMCrypto(conf *TPM) (TPM, error) {

	if conf.X509Certificate != nil && conf.PublicCertFile != "" {
		return TPM{}, fmt.Errorf("salrashid123/signer: Either X509Certificate or a the path to the certificate must be specified; not both")
	}
	if conf.TpmDevice == nil {
		return TPM{}, fmt.Errorf("salrashid123/signer: TpmDevice must be specified")
	}

	rwr := transport.FromReadWriter(conf.TpmDevice)

	// todo: we should supply the encrypted session here, if set
	pub, err := tpm2.ReadPublic{
		ObjectHandle: tpm2.TPMIDHObject(conf.Handle.HandleValue()),
	}.Execute(rwr)
	if err != nil {
		return TPM{}, fmt.Errorf("salrashid123/signer: Unable to Read Public data from TPM: %v", err)
	}
	conf.name = pub.Name

	pc, err := pub.OutPublic.Contents()
	if err != nil {
		return TPM{}, fmt.Errorf("salrashid123/signer: Unable to Read Public content TPM: %v", err)
	}
	conf.tpmPublic = *pc
	if pc.Type == tpm2.TPMAlgRSA {
		rsaDetail, err := pc.Parameters.RSADetail()
		if err != nil {
			return TPM{}, fmt.Errorf("salrashid123/signer: Unable to Read Public rsa parameters TPM: %v", err)
		}

		rsaUnique, err := pc.Unique.RSA()
		if err != nil {
			return TPM{}, fmt.Errorf("salrashid123/signer: Unable to Read Public rsa unique TPM: %v", err)
		}
		rsaPub, err := tpm2.RSAPub(rsaDetail, rsaUnique)
		if err != nil {
			return TPM{}, fmt.Errorf("salrashid123/signer: Unable to create RSAPublic TPM: %v", err)
		}

		conf.publicKey = rsaPub
	} else if pc.Type == tpm2.TPMAlgECC {
		ecDetail, err := pc.Parameters.ECCDetail()
		if err != nil {
			return TPM{}, fmt.Errorf("salrashid123/signer: Unable to Read Public ec parameters TPM: %v", err)
		}
		crv, err := ecDetail.CurveID.Curve()
		if err != nil {
			return TPM{}, fmt.Errorf("salrashid123/signer: Unable to Read Public ec curve TPM: %v", err)
		}
		eccUnique, err := pc.Unique.ECC()
		if err != nil {
			return TPM{}, fmt.Errorf("salrashid123/signer: Unable to Read Public ec unique TPM: %v", err)
		}
		conf.publicKey = &ecdsa.PublicKey{
			Curve: crv,
			X:     big.NewInt(0).SetBytes(eccUnique.X.Buffer),
			Y:     big.NewInt(0).SetBytes(eccUnique.Y.Buffer),
		}
	} else {
		return TPM{}, fmt.Errorf("salrashid123/signer: Unsupported key type: %v", pc.Type)
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

	if t.EncryptionHandle != 0 {
		encryptionPub, err := tpm2.ReadPublic{
			ObjectHandle: t.EncryptionHandle,
		}.Execute(rwr)
		if err != nil {
			return nil, err
		}
		ePubName, err := encryptionPub.OutPublic.Contents()
		if err != nil {
			return nil, err
		}
		sess = tpm2.HMAC(tpm2.TPMAlgSHA256, 16, tpm2.AESEncryption(128, tpm2.EncryptIn), tpm2.Salted(t.EncryptionHandle, *ePubName))
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
			return nil, fmt.Errorf("signer: unknown hash function %v", opts.HashFunc())
		}
	}

	var se tpm2.Session
	if t.AuthSession != nil {
		var err error
		var closer func() error
		se, closer, err = t.AuthSession.GetSession()
		if err != nil {
			return nil, fmt.Errorf("signer: error getting session %s", err)
		}
		defer closer()
	} else {
		se = tpm2.PasswordAuth(nil)
	}

	var tsig []byte
	switch t.publicKey.(type) {
	case *rsa.PublicKey:
		rd, err := t.tpmPublic.Parameters.RSADetail()
		if err != nil {
			return nil, fmt.Errorf("signer: can't error getting rsa details %v", err)
		}
		rspSign, err := tpm2.Sign{
			KeyHandle: tpm2.AuthHandle{
				Handle: t.Handle,
				Name:   t.name,
				Auth:   se,
			},

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
			return nil, fmt.Errorf("signer: can't Sign: %v", err)
		}

		var rsig *tpm2.TPMSSignatureRSA
		if rspSign.Signature.SigAlg == tpm2.TPMAlgRSASSA {
			rsig, err = rspSign.Signature.Signature.RSASSA()
			if err != nil {
				return nil, fmt.Errorf("signer: error getting rsa ssa signature: %v", err)
			}
		} else if rspSign.Signature.SigAlg == tpm2.TPMAlgRSAPSS {
			rsig, err = rspSign.Signature.Signature.RSAPSS()
			if err != nil {
				return nil, fmt.Errorf("signer: error getting rsa pss signature: %v", err)
			}
		} else {
			return nil, fmt.Errorf("signer: unsupported signature algorithm't Sign: %v", err)
		}

		tsig = rsig.Sig.Buffer
	case *ecdsa.PublicKey:
		rd, err := t.tpmPublic.Parameters.ECCDetail()
		if err != nil {
			return nil, fmt.Errorf("tpmjwt: can't error getting rsa details %v", err)
		}
		rspSign, err := tpm2.Sign{
			KeyHandle: tpm2.AuthHandle{
				Handle: t.Handle,
				Name:   t.name,
				Auth:   se,
			},

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

	if t.X509Certificate == nil {
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
		t.X509Certificate = pub
	}

	var privKey crypto.PrivateKey = t
	return tls.Certificate{
		PrivateKey:  privKey,
		Leaf:        t.X509Certificate,
		Certificate: [][]byte{t.X509Certificate.Raw},
	}, nil
}

type Session interface {
	GetSession() (auth tpm2.Session, closer func() error, err error) // this supplies the session handle to the library
}

// for pcr sessions
type PCRSession struct {
	rwr transport.TPM
	sel []tpm2.TPMSPCRSelection
	_   Session
}

func NewPCRSession(rwr transport.TPM, sel []tpm2.TPMSPCRSelection) (PCRSession, error) {
	return PCRSession{rwr, sel, nil}, nil
}

func (p PCRSession) GetSession() (auth tpm2.Session, closer func() error, err error) {
	sess, closer, err := tpm2.PolicySession(p.rwr, tpm2.TPMAlgSHA256, 16)
	if err != nil {
		return nil, nil, err
	}
	_, err = tpm2.PolicyPCR{
		PolicySession: sess.Handle(),
		Pcrs: tpm2.TPMLPCRSelection{
			PCRSelections: p.sel,
		},
	}.Execute(p.rwr)
	if err != nil {
		return nil, nil, err
	}
	return sess, closer, nil
}

// for password sessions
type PasswordSession struct {
	rwr      transport.TPM
	password []byte
	_        Session
}

func NewPasswordSession(rwr transport.TPM, password []byte) (PasswordSession, error) {
	return PasswordSession{rwr, password, nil}, nil
}

func (p PasswordSession) GetSession() (auth tpm2.Session, closer func() error, err error) {
	c := func() error { return nil }
	return tpm2.PasswordAuth(p.password), c, nil
}

type PolicyAuthValueDuplicateSelectSession struct {
	rwr      transport.TPM
	password []byte
	ekName   tpm2.TPM2BName
	_        Session
}

func NewPolicyAuthValueAndDuplicateSelectSession(rwr transport.TPM, password []byte, ekName tpm2.TPM2BName) (PolicyAuthValueDuplicateSelectSession, error) {
	return PolicyAuthValueDuplicateSelectSession{rwr, password, ekName, nil}, nil
}

func (p PolicyAuthValueDuplicateSelectSession) GetSession() (auth tpm2.Session, closer func() error, err error) {

	pa_sess, pa_cleanup, err := tpm2.PolicySession(p.rwr, tpm2.TPMAlgSHA256, 16)
	if err != nil {
		return nil, nil, err
	}
	//defer pa_cleanup()

	_, err = tpm2.PolicyAuthValue{
		PolicySession: pa_sess.Handle(),
	}.Execute(p.rwr)
	if err != nil {
		return nil, nil, err
	}

	papgd, err := tpm2.PolicyGetDigest{
		PolicySession: pa_sess.Handle(),
	}.Execute(p.rwr)
	if err != nil {
		return nil, nil, err
	}
	err = pa_cleanup()
	if err != nil {
		return nil, nil, err
	}
	// as the "new parent"
	dupselect_sess, dupselect_cleanup, err := tpm2.PolicySession(p.rwr, tpm2.TPMAlgSHA256, 16)
	if err != nil {
		return nil, nil, err
	}
	//defer dupselect_cleanup()

	_, err = tpm2.PolicyDuplicationSelect{
		PolicySession: dupselect_sess.Handle(),
		NewParentName: tpm2.TPM2BName(p.ekName),
	}.Execute(p.rwr)
	if err != nil {
		return nil, nil, err
	}

	// calculate the digest
	dupselpgd, err := tpm2.PolicyGetDigest{
		PolicySession: dupselect_sess.Handle(),
	}.Execute(p.rwr)
	if err != nil {
		return nil, nil, err
	}
	err = dupselect_cleanup()
	if err != nil {
		return nil, nil, err
	}
	// now create an OR session with the two above policies above
	or_sess, or_cleanup, err := tpm2.PolicySession(p.rwr, tpm2.TPMAlgSHA256, 16, []tpm2.AuthOption{tpm2.Auth([]byte(p.password))}...)
	if err != nil {
		return nil, nil, err
	}
	//defer or_cleanup()

	_, err = tpm2.PolicyAuthValue{
		PolicySession: or_sess.Handle(),
	}.Execute(p.rwr)
	if err != nil {
		return nil, nil, err
	}
	_, err = tpm2.PolicyOr{
		PolicySession: or_sess.Handle(),
		PHashList:     tpm2.TPMLDigest{Digests: []tpm2.TPM2BDigest{papgd.PolicyDigest, dupselpgd.PolicyDigest}},
	}.Execute(p.rwr)
	if err != nil {
		return nil, nil, err
	}

	return or_sess, or_cleanup, nil
}

type PCRAndDuplicateSelectSession struct {
	rwr      transport.TPM
	sel      []tpm2.TPMSPCRSelection
	password []byte
	ekName   tpm2.TPM2BName
	_        Session
}

func NewPCRAndDuplicateSelectSession(rwr transport.TPM, sel []tpm2.TPMSPCRSelection, password []byte, ekName tpm2.TPM2BName) (PCRAndDuplicateSelectSession, error) {
	return PCRAndDuplicateSelectSession{rwr, sel, password, ekName, nil}, nil
}

func (p PCRAndDuplicateSelectSession) GetSession() (auth tpm2.Session, closer func() error, err error) {

	pcr_sess, pcr_cleanup, err := tpm2.PolicySession(p.rwr, tpm2.TPMAlgSHA256, 16)
	if err != nil {
		return nil, nil, err
	}

	_, err = tpm2.PolicyPCR{
		PolicySession: pcr_sess.Handle(),
		Pcrs: tpm2.TPMLPCRSelection{
			PCRSelections: p.sel,
		},
	}.Execute(p.rwr)
	if err != nil {
		return nil, nil, err
	}

	pcrpgd, err := tpm2.PolicyGetDigest{
		PolicySession: pcr_sess.Handle(),
	}.Execute(p.rwr)
	if err != nil {
		return nil, nil, err
	}
	err = pcr_cleanup()
	if err != nil {
		return nil, nil, err
	}

	// create another real session with the PolicyDuplicationSelect and remember to specify the EK
	// as the "new parent"
	dupselect_sess, dupselect_cleanup, err := tpm2.PolicySession(p.rwr, tpm2.TPMAlgSHA256, 16)
	if err != nil {
		return nil, nil, err
	}

	_, err = tpm2.PolicyDuplicationSelect{
		PolicySession: dupselect_sess.Handle(),
		NewParentName: p.ekName,
	}.Execute(p.rwr)
	if err != nil {
		return nil, nil, err
	}

	// calculate the digest
	dupselpgd, err := tpm2.PolicyGetDigest{
		PolicySession: dupselect_sess.Handle(),
	}.Execute(p.rwr)
	if err != nil {
		return nil, nil, err
	}
	err = dupselect_cleanup()
	if err != nil {
		return nil, nil, err
	}

	// now create an OR session with the two above policies above
	or_sess, or_cleanup, err := tpm2.PolicySession(p.rwr, tpm2.TPMAlgSHA256, 16)
	if err != nil {
		return nil, nil, err
	}
	//defer or_cleanup()

	_, err = tpm2.PolicyPCR{
		PolicySession: or_sess.Handle(),
		Pcrs: tpm2.TPMLPCRSelection{
			PCRSelections: p.sel,
		},
	}.Execute(p.rwr)
	if err != nil {
		return nil, nil, err
	}

	_, err = tpm2.PolicyOr{
		PolicySession: or_sess.Handle(),
		PHashList:     tpm2.TPMLDigest{Digests: []tpm2.TPM2BDigest{pcrpgd.PolicyDigest, dupselpgd.PolicyDigest}},
	}.Execute(p.rwr)
	if err != nil {
		return nil, nil, err
	}

	return or_sess, or_cleanup, nil
}
