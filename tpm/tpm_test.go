package tpm

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"math/big"
	"os"
	"testing"

	"github.com/google/go-tpm-tools/simulator"
	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/stretchr/testify/require"
)

var (
	rsaTemplate = tpm2.TPMTPublic{
		Type:    tpm2.TPMAlgRSA,
		NameAlg: tpm2.TPMAlgSHA256,
		ObjectAttributes: tpm2.TPMAObject{
			SignEncrypt:         true,
			FixedTPM:            true,
			FixedParent:         true,
			SensitiveDataOrigin: true,
			UserWithAuth:        true,
		},
		AuthPolicy: tpm2.TPM2BDigest{},
		Parameters: tpm2.NewTPMUPublicParms(
			tpm2.TPMAlgRSA,
			&tpm2.TPMSRSAParms{
				Scheme: tpm2.TPMTRSAScheme{
					Scheme: tpm2.TPMAlgRSASSA,
					Details: tpm2.NewTPMUAsymScheme(
						tpm2.TPMAlgRSASSA,
						&tpm2.TPMSSigSchemeRSASSA{
							HashAlg: tpm2.TPMAlgSHA256,
						},
					),
				},
				KeyBits: 2048,
			},
		),
		Unique: tpm2.NewTPMUPublicID(
			tpm2.TPMAlgRSA,
			&tpm2.TPM2BPublicKeyRSA{
				Buffer: make([]byte, 256),
			},
		),
	}

	rsaTemplateNoUserWithAuth = tpm2.TPMTPublic{
		Type:    tpm2.TPMAlgRSA,
		NameAlg: tpm2.TPMAlgSHA256,
		ObjectAttributes: tpm2.TPMAObject{
			SignEncrypt:         true,
			FixedTPM:            true,
			FixedParent:         true,
			SensitiveDataOrigin: true,
			UserWithAuth:        false,
		},
		AuthPolicy: tpm2.TPM2BDigest{},
		Parameters: tpm2.NewTPMUPublicParms(
			tpm2.TPMAlgRSA,
			&tpm2.TPMSRSAParms{
				Scheme: tpm2.TPMTRSAScheme{
					Scheme: tpm2.TPMAlgRSASSA,
					Details: tpm2.NewTPMUAsymScheme(
						tpm2.TPMAlgRSASSA,
						&tpm2.TPMSSigSchemeRSASSA{
							HashAlg: tpm2.TPMAlgSHA256,
						},
					),
				},
				KeyBits: 2048,
			},
		),
		Unique: tpm2.NewTPMUPublicID(
			tpm2.TPMAlgRSA,
			&tpm2.TPM2BPublicKeyRSA{
				Buffer: make([]byte, 256),
			},
		),
	}

	rsaPSSTemplate = tpm2.TPMTPublic{
		Type:    tpm2.TPMAlgRSA,
		NameAlg: tpm2.TPMAlgSHA256,
		ObjectAttributes: tpm2.TPMAObject{
			SignEncrypt:         true,
			FixedTPM:            true,
			FixedParent:         true,
			SensitiveDataOrigin: true,
			UserWithAuth:        true,
		},
		AuthPolicy: tpm2.TPM2BDigest{},
		Parameters: tpm2.NewTPMUPublicParms(
			tpm2.TPMAlgRSA,
			&tpm2.TPMSRSAParms{
				Scheme: tpm2.TPMTRSAScheme{
					Scheme: tpm2.TPMAlgRSAPSS,
					Details: tpm2.NewTPMUAsymScheme(
						tpm2.TPMAlgRSAPSS,
						&tpm2.TPMSSigSchemeRSAPSS{
							HashAlg: tpm2.TPMAlgSHA256,
						},
					),
				},
				KeyBits: 2048,
			},
		),
		Unique: tpm2.NewTPMUPublicID(
			tpm2.TPMAlgRSA,
			&tpm2.TPM2BPublicKeyRSA{
				Buffer: make([]byte, 256),
			},
		),
	}

	eccTemplate = tpm2.TPMTPublic{
		Type:    tpm2.TPMAlgECC,
		NameAlg: tpm2.TPMAlgSHA256,
		ObjectAttributes: tpm2.TPMAObject{
			SignEncrypt:         true,
			FixedTPM:            true,
			FixedParent:         true,
			SensitiveDataOrigin: true,
			UserWithAuth:        true,
		},
		AuthPolicy: tpm2.TPM2BDigest{},
		Parameters: tpm2.NewTPMUPublicParms(
			tpm2.TPMAlgECC,
			&tpm2.TPMSECCParms{
				Scheme: tpm2.TPMTECCScheme{
					Scheme: tpm2.TPMAlgECDSA,
					Details: tpm2.NewTPMUAsymScheme(
						tpm2.TPMAlgECDSA,
						&tpm2.TPMSSigSchemeECDSA{
							HashAlg: tpm2.TPMAlgSHA256,
						},
					),
				},
				CurveID: tpm2.TPMECCNistP256,
			},
		),
		Unique: tpm2.NewTPMUPublicID(
			tpm2.TPMAlgECC,
			&tpm2.TPMSECCPoint{
				X: tpm2.TPM2BECCParameter{
					Buffer: make([]byte, 32),
				},
				Y: tpm2.TPM2BECCParameter{
					Buffer: make([]byte, 32),
				},
			},
		),
	}
)

func TestTPMPublic(t *testing.T) {
	tpmDevice, err := simulator.Get()
	require.NoError(t, err)
	defer tpmDevice.Close()

	rwr := transport.FromReadWriter(tpmDevice)
	primaryKey, err := tpm2.CreatePrimary{
		PrimaryHandle: tpm2.TPMRHOwner,
		InPublic:      tpm2.New2B(tpm2.RSASRKTemplate),
	}.Execute(rwr)
	require.NoError(t, err)
	defer func() {
		flushContextCmd := tpm2.FlushContext{
			FlushHandle: primaryKey.ObjectHandle,
		}
		_, _ = flushContextCmd.Execute(rwr)
	}()

	rsaKeyResponse, err := tpm2.CreateLoaded{
		ParentHandle: tpm2.AuthHandle{
			Handle: primaryKey.ObjectHandle,
			Name:   primaryKey.Name,
			Auth:   tpm2.PasswordAuth(nil),
		},
		InPublic: tpm2.New2BTemplate(&rsaTemplate),
	}.Execute(rwr)
	require.NoError(t, err)

	pub, err := tpm2.ReadPublic{
		ObjectHandle: rsaKeyResponse.ObjectHandle,
	}.Execute(rwr)
	require.NoError(t, err)

	defer func() {
		flushContextCmd := tpm2.FlushContext{
			FlushHandle: rsaKeyResponse.ObjectHandle,
		}
		_, _ = flushContextCmd.Execute(rwr)
	}()

	conf := TPM{
		TpmDevice: tpmDevice,
		NamedHandle: &tpm2.NamedHandle{
			Handle: rsaKeyResponse.ObjectHandle,
			Name:   pub.Name,
		},
	}

	tpm, err := NewTPMCrypto(&conf)
	require.NoError(t, err)

	pubKey := tpm.Public()
	rsaPubKey, ok := pubKey.(*rsa.PublicKey)
	require.True(t, ok)
	// https://github.com/google/go-tpm-tools/blob/v0.4.0/client/template.go#L45
	require.Equal(t, 2048, rsaPubKey.Size()*8)
}

func TestTPMSignRSA(t *testing.T) {
	tpmDevice, err := simulator.Get()
	require.NoError(t, err)
	defer tpmDevice.Close()

	rwr := transport.FromReadWriter(tpmDevice)
	primaryKey, err := tpm2.CreatePrimary{
		PrimaryHandle: tpm2.TPMRHOwner,
		InPublic:      tpm2.New2B(tpm2.RSASRKTemplate),
	}.Execute(rwr)
	require.NoError(t, err)

	defer func() {
		flushContextCmd := tpm2.FlushContext{
			FlushHandle: primaryKey.ObjectHandle,
		}
		_, _ = flushContextCmd.Execute(rwr)
	}()

	rsaKeyResponse, err := tpm2.CreateLoaded{
		ParentHandle: tpm2.AuthHandle{
			Handle: primaryKey.ObjectHandle,
			Name:   primaryKey.Name,
			Auth:   tpm2.PasswordAuth(nil),
		},
		InPublic: tpm2.New2BTemplate(&rsaTemplate),
	}.Execute(rwr)
	require.NoError(t, err)
	defer func() {
		flushContextCmd := tpm2.FlushContext{
			FlushHandle: rsaKeyResponse.ObjectHandle,
		}
		_, _ = flushContextCmd.Execute(rwr)
	}()

	pub, err := tpm2.ReadPublic{
		ObjectHandle: rsaKeyResponse.ObjectHandle,
	}.Execute(rwr)
	require.NoError(t, err)

	outPub, err := pub.OutPublic.Contents()
	require.NoError(t, err)

	rsaDetail, err := outPub.Parameters.RSADetail()
	require.NoError(t, err)

	rsaUnique, err := outPub.Unique.RSA()
	require.NoError(t, err)

	pubKey, err := tpm2.RSAPub(rsaDetail, rsaUnique)
	require.NoError(t, err)

	conf := TPM{
		TpmDevice: tpmDevice,
		NamedHandle: &tpm2.NamedHandle{
			Handle: rsaKeyResponse.ObjectHandle,
			Name:   pub.Name,
		},
	}

	tpm, err := NewTPMCrypto(&conf)
	require.NoError(t, err)

	hash := crypto.SHA256.New()
	hash.Write([]byte("test digest"))
	digest := hash.Sum(nil)

	signature, err := tpm.Sign(tpmDevice, digest, nil)
	require.NoError(t, err)

	err = rsa.VerifyPKCS1v15(pubKey, crypto.SHA256, digest, signature)
	require.NoError(t, err)
}

func TestTPMSignRSAFail(t *testing.T) {
	tpmDevice, err := simulator.Get()
	require.NoError(t, err)
	defer tpmDevice.Close()

	rwr := transport.FromReadWriter(tpmDevice)
	primaryKey, err := tpm2.CreatePrimary{
		PrimaryHandle: tpm2.TPMRHOwner,
		InPublic:      tpm2.New2B(tpm2.RSASRKTemplate),
	}.Execute(rwr)
	require.NoError(t, err)

	defer func() {
		flushContextCmd := tpm2.FlushContext{
			FlushHandle: primaryKey.ObjectHandle,
		}
		_, _ = flushContextCmd.Execute(rwr)
	}()

	rsaKeyResponse, err := tpm2.CreateLoaded{
		ParentHandle: tpm2.AuthHandle{
			Handle: primaryKey.ObjectHandle,
			Name:   primaryKey.Name,
			Auth:   tpm2.PasswordAuth(nil),
		},
		InPublic: tpm2.New2BTemplate(&rsaTemplate),
	}.Execute(rwr)
	require.NoError(t, err)
	defer func() {
		flushContextCmd := tpm2.FlushContext{
			FlushHandle: rsaKeyResponse.ObjectHandle,
		}
		_, _ = flushContextCmd.Execute(rwr)
	}()

	pub, err := tpm2.ReadPublic{
		ObjectHandle: rsaKeyResponse.ObjectHandle,
	}.Execute(rwr)
	require.NoError(t, err)

	outPub, err := pub.OutPublic.Contents()
	require.NoError(t, err)

	rsaDetail, err := outPub.Parameters.RSADetail()
	require.NoError(t, err)

	rsaUnique, err := outPub.Unique.RSA()
	require.NoError(t, err)

	pubKey, err := tpm2.RSAPub(rsaDetail, rsaUnique)
	require.NoError(t, err)

	conf := TPM{
		TpmDevice: tpmDevice,
		NamedHandle: &tpm2.NamedHandle{
			Handle: rsaKeyResponse.ObjectHandle,
			Name:   pub.Name,
		},
	}

	tpm, err := NewTPMCrypto(&conf)
	require.NoError(t, err)

	hash := crypto.SHA256.New()
	hash.Write([]byte("test digest"))
	digest := hash.Sum(nil)

	signature, err := tpm.Sign(tpmDevice, digest, nil)
	require.NoError(t, err)

	err = rsa.VerifyPKCS1v15(pubKey, crypto.SHA256, []byte("another test digest"), signature)
	require.Error(t, err)
}

func TestTPMSignRSAPSS(t *testing.T) {
	tpmDevice, err := simulator.Get()
	require.NoError(t, err)
	defer tpmDevice.Close()

	rwr := transport.FromReadWriter(tpmDevice)
	primaryKey, err := tpm2.CreatePrimary{
		PrimaryHandle: tpm2.TPMRHOwner,
		InPublic:      tpm2.New2B(tpm2.RSASRKTemplate),
	}.Execute(rwr)
	require.NoError(t, err)

	defer func() {
		flushContextCmd := tpm2.FlushContext{
			FlushHandle: primaryKey.ObjectHandle,
		}
		_, _ = flushContextCmd.Execute(rwr)
	}()

	rsaKeyResponse, err := tpm2.CreateLoaded{
		ParentHandle: tpm2.AuthHandle{
			Handle: primaryKey.ObjectHandle,
			Name:   primaryKey.Name,
			Auth:   tpm2.PasswordAuth(nil),
		},
		InPublic: tpm2.New2BTemplate(&rsaPSSTemplate),
	}.Execute(rwr)
	require.NoError(t, err)
	defer func() {
		flushContextCmd := tpm2.FlushContext{
			FlushHandle: rsaKeyResponse.ObjectHandle,
		}
		_, _ = flushContextCmd.Execute(rwr)
	}()

	pub, err := tpm2.ReadPublic{
		ObjectHandle: rsaKeyResponse.ObjectHandle,
	}.Execute(rwr)
	require.NoError(t, err)

	outPub, err := pub.OutPublic.Contents()
	require.NoError(t, err)

	rsaDetail, err := outPub.Parameters.RSADetail()
	require.NoError(t, err)

	rsaUnique, err := outPub.Unique.RSA()
	require.NoError(t, err)

	pubKey, err := tpm2.RSAPub(rsaDetail, rsaUnique)
	require.NoError(t, err)

	conf := TPM{
		TpmDevice: tpmDevice,
		NamedHandle: &tpm2.NamedHandle{
			Handle: rsaKeyResponse.ObjectHandle,
			Name:   pub.Name,
		},
	}

	tpm, err := NewTPMCrypto(&conf)
	require.NoError(t, err)

	hash := crypto.SHA256.New()
	hash.Write([]byte("test digest"))
	digest := hash.Sum(nil)

	signature, err := tpm.Sign(tpmDevice, digest, nil)
	require.NoError(t, err)

	opts := &rsa.PSSOptions{
		Hash:       crypto.SHA256,
		SaltLength: rsa.PSSSaltLengthAuto,
	}
	err = rsa.VerifyPSS(pubKey, crypto.SHA256, digest, signature, opts)
	require.NoError(t, err)
}

func TestTPMSignECC(t *testing.T) {
	tpmDevice, err := simulator.Get()
	require.NoError(t, err)
	defer tpmDevice.Close()

	rwr := transport.FromReadWriter(tpmDevice)
	primaryKey, err := tpm2.CreatePrimary{
		PrimaryHandle: tpm2.TPMRHOwner,
		InPublic:      tpm2.New2B(tpm2.RSASRKTemplate),
	}.Execute(rwr)
	require.NoError(t, err)

	defer func() {
		flushContextCmd := tpm2.FlushContext{
			FlushHandle: primaryKey.ObjectHandle,
		}
		_, _ = flushContextCmd.Execute(rwr)
	}()

	eccKeyResponse, err := tpm2.CreateLoaded{
		ParentHandle: tpm2.AuthHandle{
			Handle: primaryKey.ObjectHandle,
			Name:   primaryKey.Name,
			Auth:   tpm2.PasswordAuth(nil),
		},
		InPublic: tpm2.New2BTemplate(&eccTemplate),
	}.Execute(rwr)
	require.NoError(t, err)
	defer func() {
		flushContextCmd := tpm2.FlushContext{
			FlushHandle: eccKeyResponse.ObjectHandle,
		}
		_, _ = flushContextCmd.Execute(rwr)
	}()

	pub, err := tpm2.ReadPublic{
		ObjectHandle: eccKeyResponse.ObjectHandle,
	}.Execute(rwr)
	require.NoError(t, err)

	outPub, err := pub.OutPublic.Contents()
	require.NoError(t, err)

	eccDetail, err := outPub.Parameters.ECCDetail()
	require.NoError(t, err)

	ecUnique, err := outPub.Unique.ECC()
	require.NoError(t, err)

	crv, err := eccDetail.CurveID.Curve()
	require.NoError(t, err)

	pubKey := &ecdsa.PublicKey{
		Curve: crv,
		X:     big.NewInt(0).SetBytes(ecUnique.X.Buffer),
		Y:     big.NewInt(0).SetBytes(ecUnique.Y.Buffer),
	}

	conf := TPM{
		TpmDevice: tpmDevice,
		NamedHandle: &tpm2.NamedHandle{
			Handle: eccKeyResponse.ObjectHandle,
			Name:   pub.Name,
		},
	}

	tpm, err := NewTPMCrypto(&conf)
	require.NoError(t, err)

	hash := crypto.SHA256.New()
	hash.Write([]byte("test digest"))
	digest := hash.Sum(nil)

	signature, err := tpm.Sign(tpmDevice, digest, nil)
	require.NoError(t, err)

	ok := ecdsa.VerifyASN1(pubKey, digest[:], signature)
	require.True(t, ok)
}

func TestTPMSignECCRAW(t *testing.T) {
	tpmDevice, err := simulator.Get()
	require.NoError(t, err)
	defer tpmDevice.Close()

	rwr := transport.FromReadWriter(tpmDevice)
	primaryKey, err := tpm2.CreatePrimary{
		PrimaryHandle: tpm2.TPMRHOwner,
		InPublic:      tpm2.New2B(tpm2.RSASRKTemplate),
	}.Execute(rwr)
	require.NoError(t, err)

	defer func() {
		flushContextCmd := tpm2.FlushContext{
			FlushHandle: primaryKey.ObjectHandle,
		}
		_, _ = flushContextCmd.Execute(rwr)
	}()

	eccKeyResponse, err := tpm2.CreateLoaded{
		ParentHandle: tpm2.AuthHandle{
			Handle: primaryKey.ObjectHandle,
			Name:   primaryKey.Name,
			Auth:   tpm2.PasswordAuth(nil),
		},
		InPublic: tpm2.New2BTemplate(&eccTemplate),
	}.Execute(rwr)
	require.NoError(t, err)
	defer func() {
		flushContextCmd := tpm2.FlushContext{
			FlushHandle: eccKeyResponse.ObjectHandle,
		}
		_, _ = flushContextCmd.Execute(rwr)
	}()

	pub, err := tpm2.ReadPublic{
		ObjectHandle: eccKeyResponse.ObjectHandle,
	}.Execute(rwr)
	require.NoError(t, err)

	outPub, err := pub.OutPublic.Contents()
	require.NoError(t, err)

	eccDetail, err := outPub.Parameters.ECCDetail()
	require.NoError(t, err)

	ecUnique, err := outPub.Unique.ECC()
	require.NoError(t, err)

	crv, err := eccDetail.CurveID.Curve()
	require.NoError(t, err)

	pubKey := &ecdsa.PublicKey{
		Curve: crv,
		X:     big.NewInt(0).SetBytes(ecUnique.X.Buffer),
		Y:     big.NewInt(0).SetBytes(ecUnique.Y.Buffer),
	}

	conf := TPM{
		TpmDevice: tpmDevice,
		NamedHandle: &tpm2.NamedHandle{
			Handle: eccKeyResponse.ObjectHandle,
			Name:   pub.Name,
		},
		ECCRawOutput: true,
	}

	tpm, err := NewTPMCrypto(&conf)
	require.NoError(t, err)

	hash := crypto.SHA256.New()
	hash.Write([]byte("test digest"))
	digest := hash.Sum(nil)

	signature, err := tpm.Sign(tpmDevice, digest, nil)
	require.NoError(t, err)

	curveBits := pubKey.Curve.Params().BitSize
	keyBytes := curveBits / 8
	if curveBits%8 > 0 {
		keyBytes += 1
	}

	x := big.NewInt(0).SetBytes(signature[:keyBytes])
	y := big.NewInt(0).SetBytes(signature[keyBytes:])

	ok := ecdsa.Verify(pubKey, digest[:], x, y)
	require.True(t, ok)
}

func TestTPMSignPCRPolicy(t *testing.T) {
	tpmDevice, err := simulator.Get()
	require.NoError(t, err)
	defer tpmDevice.Close()

	rwr := transport.FromReadWriter(tpmDevice)
	primaryKey, err := tpm2.CreatePrimary{
		PrimaryHandle: tpm2.TPMRHOwner,
		InPublic:      tpm2.New2B(tpm2.RSASRKTemplate),
	}.Execute(rwr)
	require.NoError(t, err)
	defer func() {
		flushContextCmd := tpm2.FlushContext{
			FlushHandle: primaryKey.ObjectHandle,
		}
		_, _ = flushContextCmd.Execute(rwr)
	}()

	pcr := 23

	sess, cleanup, err := tpm2.PolicySession(rwr, tpm2.TPMAlgSHA256, 16, tpm2.Trial())
	require.NoError(t, err)
	defer cleanup()

	_, err = tpm2.PolicyPCR{
		PolicySession: sess.Handle(),
		Pcrs: tpm2.TPMLPCRSelection{
			PCRSelections: []tpm2.TPMSPCRSelection{
				{
					Hash:      tpm2.TPMAlgSHA256,
					PCRSelect: tpm2.PCClientCompatible.PCRs(uint(pcr)),
				},
			},
		},
	}.Execute(rwr)
	require.NoError(t, err)

	pgd, err := tpm2.PolicyGetDigest{
		PolicySession: sess.Handle(),
	}.Execute(rwr)
	require.NoError(t, err)

	_, err = tpm2.FlushContext{FlushHandle: sess.Handle()}.Execute(rwr)
	require.NoError(t, err)

	rsaTemplateNoUserWithAuth.AuthPolicy = tpm2.TPM2BDigest{
		Buffer: pgd.PolicyDigest.Buffer,
	}

	rsaKeyResponse, err := tpm2.CreateLoaded{
		ParentHandle: tpm2.AuthHandle{
			Handle: primaryKey.ObjectHandle,
			Name:   primaryKey.Name,
			Auth:   tpm2.PasswordAuth(nil),
		},
		InPublic: tpm2.New2BTemplate(&rsaTemplateNoUserWithAuth),
	}.Execute(rwr)
	require.NoError(t, err)

	defer func() {
		flushContextCmd := tpm2.FlushContext{
			FlushHandle: rsaKeyResponse.ObjectHandle,
		}
		_, _ = flushContextCmd.Execute(rwr)
	}()

	pub, err := tpm2.ReadPublic{
		ObjectHandle: rsaKeyResponse.ObjectHandle,
	}.Execute(rwr)
	require.NoError(t, err)

	outPub, err := pub.OutPublic.Contents()
	require.NoError(t, err)

	rsaDetail, err := outPub.Parameters.RSADetail()
	require.NoError(t, err)

	rsaUnique, err := outPub.Unique.RSA()
	require.NoError(t, err)

	pubKey, err := tpm2.RSAPub(rsaDetail, rsaUnique)
	require.NoError(t, err)

	p, err := NewPCRSession(rwr, []tpm2.TPMSPCRSelection{
		{
			Hash:      tpm2.TPMAlgSHA256,
			PCRSelect: tpm2.PCClientCompatible.PCRs(uint(pcr)),
		},
	})
	require.NoError(t, err)

	conf := TPM{
		TpmDevice: tpmDevice,
		NamedHandle: &tpm2.NamedHandle{
			Handle: rsaKeyResponse.ObjectHandle,
			Name:   pub.Name,
		},
		AuthSession: p,
	}

	tpm, err := NewTPMCrypto(&conf)
	require.NoError(t, err)

	hash := crypto.SHA256.New()
	hash.Write([]byte("test digest"))
	digest := hash.Sum(nil)

	signature, err := tpm.Sign(tpmDevice, digest, nil)
	require.NoError(t, err)

	err = rsa.VerifyPKCS1v15(pubKey, crypto.SHA256, digest, signature)
	require.NoError(t, err)
}

func TestTPMSignPolicyFail(t *testing.T) {
	tpmDevice, err := simulator.Get()
	require.NoError(t, err)
	defer tpmDevice.Close()

	rwr := transport.FromReadWriter(tpmDevice)
	primaryKey, err := tpm2.CreatePrimary{
		PrimaryHandle: tpm2.TPMRHOwner,
		InPublic:      tpm2.New2B(tpm2.RSASRKTemplate),
	}.Execute(rwr)
	require.NoError(t, err)
	defer func() {
		flushContextCmd := tpm2.FlushContext{
			FlushHandle: primaryKey.ObjectHandle,
		}
		_, _ = flushContextCmd.Execute(rwr)
	}()

	pcr := 23

	sess, cleanup, err := tpm2.PolicySession(rwr, tpm2.TPMAlgSHA256, 16, tpm2.Trial())
	require.NoError(t, err)
	defer cleanup()

	_, err = tpm2.PolicyPCR{
		PolicySession: sess.Handle(),
		Pcrs: tpm2.TPMLPCRSelection{
			PCRSelections: []tpm2.TPMSPCRSelection{
				{
					Hash:      tpm2.TPMAlgSHA256,
					PCRSelect: tpm2.PCClientCompatible.PCRs(uint(pcr)),
				},
			},
		},
	}.Execute(rwr)
	require.NoError(t, err)

	pgd, err := tpm2.PolicyGetDigest{
		PolicySession: sess.Handle(),
	}.Execute(rwr)
	require.NoError(t, err)

	_, err = tpm2.FlushContext{FlushHandle: sess.Handle()}.Execute(rwr)
	require.NoError(t, err)

	rsaTemplateNoUserWithAuth.AuthPolicy = tpm2.TPM2BDigest{
		Buffer: pgd.PolicyDigest.Buffer,
	}

	rsaKeyResponse, err := tpm2.CreateLoaded{
		ParentHandle: tpm2.AuthHandle{
			Handle: primaryKey.ObjectHandle,
			Name:   primaryKey.Name,
			Auth:   tpm2.PasswordAuth(nil),
		},
		InPublic: tpm2.New2BTemplate(&rsaTemplateNoUserWithAuth),
	}.Execute(rwr)
	require.NoError(t, err)

	defer func() {
		flushContextCmd := tpm2.FlushContext{
			FlushHandle: rsaKeyResponse.ObjectHandle,
		}
		_, _ = flushContextCmd.Execute(rwr)
	}()

	pub, err := tpm2.ReadPublic{
		ObjectHandle: rsaKeyResponse.ObjectHandle,
	}.Execute(rwr)
	require.NoError(t, err)

	/// extend pcr value

	pcrReadRsp, err := tpm2.PCRRead{
		PCRSelectionIn: tpm2.TPMLPCRSelection{
			PCRSelections: []tpm2.TPMSPCRSelection{
				{
					Hash:      tpm2.TPMAlgSHA256,
					PCRSelect: tpm2.PCClientCompatible.PCRs(uint(pcr)),
				},
			},
		},
	}.Execute(rwr)
	require.NoError(t, err)

	_, err = tpm2.PCRExtend{
		PCRHandle: tpm2.AuthHandle{
			Handle: tpm2.TPMHandle(uint(pcr)),
			Auth:   tpm2.PasswordAuth(nil),
		},
		Digests: tpm2.TPMLDigestValues{
			Digests: []tpm2.TPMTHA{
				{
					HashAlg: tpm2.TPMAlgSHA256,
					Digest:  pcrReadRsp.PCRValues.Digests[0].Buffer,
				},
			},
		},
	}.Execute(rwr)
	require.NoError(t, err)

	sess2, cleanup, err := tpm2.PolicySession(rwr, tpm2.TPMAlgSHA256, 16)
	require.NoError(t, err)
	defer cleanup()

	_, err = tpm2.PolicyPCR{
		PolicySession: sess2.Handle(),
		Pcrs: tpm2.TPMLPCRSelection{
			PCRSelections: []tpm2.TPMSPCRSelection{
				{
					Hash:      tpm2.TPMAlgSHA256,
					PCRSelect: tpm2.PCClientCompatible.PCRs(uint(pcr)),
				},
			},
		},
	}.Execute(rwr)
	require.NoError(t, err)

	p, err := NewPCRSession(rwr, []tpm2.TPMSPCRSelection{
		{
			Hash:      tpm2.TPMAlgSHA256,
			PCRSelect: tpm2.PCClientCompatible.PCRs(uint(pcr)),
		},
	})
	require.NoError(t, err)
	conf := TPM{
		TpmDevice: tpmDevice,
		NamedHandle: &tpm2.NamedHandle{
			Handle: rsaKeyResponse.ObjectHandle,
			Name:   pub.Name,
		},
		AuthSession: p,
	}

	tpm, err := NewTPMCrypto(&conf)
	require.NoError(t, err)

	hash := crypto.SHA256.New()
	hash.Write([]byte("test digest"))
	digest := hash.Sum(nil)

	_, err = tpm.Sign(tpmDevice, digest, nil)
	require.Error(t, err)

}

func TestTPMEncryption(t *testing.T) {
	tpmDevice, err := simulator.Get()
	require.NoError(t, err)
	defer tpmDevice.Close()

	rwr := transport.FromReadWriter(tpmDevice)

	createEKCmd := tpm2.CreatePrimary{
		PrimaryHandle: tpm2.TPMRHEndorsement,
		InPublic:      tpm2.New2B(tpm2.RSAEKTemplate),
	}
	createEKRsp, err := createEKCmd.Execute(rwr)
	require.NoError(t, err)
	defer func() {
		flushContextCmd := tpm2.FlushContext{
			FlushHandle: createEKRsp.ObjectHandle,
		}
		_, _ = flushContextCmd.Execute(rwr)
	}()
	encryptionPub, err := createEKRsp.OutPublic.Contents()
	require.NoError(t, err)

	primaryKey, err := tpm2.CreatePrimary{
		PrimaryHandle: tpm2.TPMRHOwner,
		InPublic:      tpm2.New2B(tpm2.RSASRKTemplate),
	}.Execute(rwr)
	require.NoError(t, err)

	defer func() {
		flushContextCmd := tpm2.FlushContext{
			FlushHandle: primaryKey.ObjectHandle,
		}
		_, _ = flushContextCmd.Execute(rwr)
	}()

	rsaKeyResponse, err := tpm2.CreateLoaded{
		ParentHandle: tpm2.AuthHandle{
			Handle: primaryKey.ObjectHandle,
			Name:   primaryKey.Name,
			Auth:   tpm2.PasswordAuth(nil),
		},
		InPublic: tpm2.New2BTemplate(&rsaTemplate),
	}.Execute(rwr)
	require.NoError(t, err)
	defer func() {
		flushContextCmd := tpm2.FlushContext{
			FlushHandle: rsaKeyResponse.ObjectHandle,
		}
		_, _ = flushContextCmd.Execute(rwr)
	}()

	pub, err := tpm2.ReadPublic{
		ObjectHandle: rsaKeyResponse.ObjectHandle,
	}.Execute(rwr)
	require.NoError(t, err)

	outPub, err := pub.OutPublic.Contents()
	require.NoError(t, err)

	rsaDetail, err := outPub.Parameters.RSADetail()
	require.NoError(t, err)

	rsaUnique, err := outPub.Unique.RSA()
	require.NoError(t, err)

	pubKey, err := tpm2.RSAPub(rsaDetail, rsaUnique)
	require.NoError(t, err)

	conf := TPM{
		TpmDevice: tpmDevice,
		NamedHandle: &tpm2.NamedHandle{
			Handle: rsaKeyResponse.ObjectHandle,
			Name:   pub.Name,
		},
		EncryptionHandle: createEKRsp.ObjectHandle,
		EncryptionPub:    encryptionPub,
	}

	tpm, err := NewTPMCrypto(&conf)
	require.NoError(t, err)

	hash := crypto.SHA256.New()
	hash.Write([]byte("test digest"))
	digest := hash.Sum(nil)

	signature, err := tpm.Sign(tpmDevice, digest, nil)
	require.NoError(t, err)

	err = rsa.VerifyPKCS1v15(pubKey, crypto.SHA256, digest, signature)
	require.NoError(t, err)
}

func TestTPMPublicCertFile(t *testing.T) {
	tpmDevice, err := simulator.Get()
	require.NoError(t, err)
	defer tpmDevice.Close()

	rwr := transport.FromReadWriter(tpmDevice)
	primaryKey, err := tpm2.CreatePrimary{
		PrimaryHandle: tpm2.TPMRHOwner,
		InPublic:      tpm2.New2B(tpm2.RSASRKTemplate),
	}.Execute(rwr)
	require.NoError(t, err)
	defer func() {
		flushContextCmd := tpm2.FlushContext{
			FlushHandle: primaryKey.ObjectHandle,
		}
		_, _ = flushContextCmd.Execute(rwr)
	}()

	rsaKeyResponse, err := tpm2.CreateLoaded{
		ParentHandle: tpm2.AuthHandle{
			Handle: primaryKey.ObjectHandle,
			Name:   primaryKey.Name,
			Auth:   tpm2.PasswordAuth(nil),
		},
		InPublic: tpm2.New2BTemplate(&rsaTemplate),
	}.Execute(rwr)
	require.NoError(t, err)

	defer func() {
		flushContextCmd := tpm2.FlushContext{
			FlushHandle: rsaKeyResponse.ObjectHandle,
		}
		_, _ = flushContextCmd.Execute(rwr)
	}()

	pubPEMData, err := os.ReadFile("../example/certs/server.crt")
	require.NoError(t, err)

	block, _ := pem.Decode(pubPEMData)
	require.NoError(t, err)

	filex509, err := x509.ParseCertificate(block.Bytes)
	require.NoError(t, err)

	conf := TPM{
		TpmDevice: tpmDevice,
		NamedHandle: &tpm2.NamedHandle{
			Handle: rsaKeyResponse.ObjectHandle,
		},
		PublicCertFile: "../example/certs/server.crt",
	}

	tpm, err := NewTPMCrypto(&conf)
	require.NoError(t, err)

	tcert, err := tpm.TLSCertificate()
	require.NoError(t, err)

	require.Equal(t, tcert.Leaf, filex509)
}

func TestTPMX509(t *testing.T) {
	tpmDevice, err := simulator.Get()
	require.NoError(t, err)
	defer tpmDevice.Close()

	rwr := transport.FromReadWriter(tpmDevice)
	primaryKey, err := tpm2.CreatePrimary{
		PrimaryHandle: tpm2.TPMRHOwner,
		InPublic:      tpm2.New2B(tpm2.RSASRKTemplate),
	}.Execute(rwr)
	require.NoError(t, err)
	defer func() {
		flushContextCmd := tpm2.FlushContext{
			FlushHandle: primaryKey.ObjectHandle,
		}
		_, _ = flushContextCmd.Execute(rwr)
	}()

	rsaKeyResponse, err := tpm2.CreateLoaded{
		ParentHandle: tpm2.AuthHandle{
			Handle: primaryKey.ObjectHandle,
			Name:   primaryKey.Name,
			Auth:   tpm2.PasswordAuth(nil),
		},
		InPublic: tpm2.New2BTemplate(&rsaTemplate),
	}.Execute(rwr)
	require.NoError(t, err)

	defer func() {
		flushContextCmd := tpm2.FlushContext{
			FlushHandle: rsaKeyResponse.ObjectHandle,
		}
		_, _ = flushContextCmd.Execute(rwr)
	}()

	pubPEMData, err := os.ReadFile("../example/certs/server.crt")
	require.NoError(t, err)

	block, _ := pem.Decode(pubPEMData)
	require.NoError(t, err)

	filex509, err := x509.ParseCertificate(block.Bytes)
	require.NoError(t, err)

	conf := TPM{
		TpmDevice: tpmDevice,
		NamedHandle: &tpm2.NamedHandle{
			Handle: rsaKeyResponse.ObjectHandle,
		},
		X509Certificate: filex509,
	}

	tpm, err := NewTPMCrypto(&conf)
	require.NoError(t, err)

	tcert, err := tpm.TLSCertificate()
	require.NoError(t, err)

	require.Equal(t, tcert.Leaf, filex509)
}
