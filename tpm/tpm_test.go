//go:build !windows

package tpm

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"math/big"
	"testing"

	"github.com/google/go-tpm-tools/client"
	"github.com/google/go-tpm-tools/simulator"
	"github.com/google/go-tpm/legacy/tpm2"
	"github.com/google/go-tpm/tpmutil"
	"github.com/stretchr/testify/require"
)

func TestTPMPublic(t *testing.T) {
	tpmDevice, err := simulator.Get()
	require.NoError(t, err)
	defer tpmDevice.Close()

	createdKey, err := client.NewKey(tpmDevice, tpm2.HandleOwner, client.SRKTemplateRSA())
	require.NoError(t, err)
	defer createdKey.Close()

	conf := TPM{
		TpmDevice: tpmDevice,
		Key:       createdKey,
	}

	tpm, err := NewTPMCrypto(&conf)
	require.NoError(t, err)

	pubKey := tpm.Public()
	rsaPubKey, ok := pubKey.(*rsa.PublicKey)
	require.True(t, ok)
	// https://github.com/google/go-tpm-tools/blob/v0.4.0/client/template.go#L45
	require.Equal(t, 2048, rsaPubKey.Size()*8)
}

// copied from https://github.com/google/go-tpm-tools/blob/v0.4.0/client/signer_test.go#L18-L24
func templateRSASSA(hash tpm2.Algorithm) tpm2.Public {
	template := client.AKTemplateRSA()
	// Can't sign arbitrary data if restricted.
	template.Attributes &= ^tpm2.FlagRestricted
	template.RSAParameters.Sign.Hash = hash
	return template
}

func templateRSAPSS(hash tpm2.Algorithm) tpm2.Public {
	template := client.AKTemplateRSA()
	// Can't sign arbitrary data if restricted.
	template.Attributes &= ^tpm2.FlagRestricted
	template.RSAParameters.Sign.Hash = hash
	template.RSAParameters.Sign.Alg = tpm2.AlgRSAPSS
	return template
}

func templateECC(hash tpm2.Algorithm) tpm2.Public {
	template := client.AKTemplateECC()
	// Can't sign arbitrary data if restricted.
	template.Attributes &= ^tpm2.FlagRestricted
	template.ECCParameters.Sign.Hash = hash
	return template
}

func TestTPMSignRSA(t *testing.T) {
	tpmDevice, err := simulator.Get()
	require.NoError(t, err)
	defer tpmDevice.Close()

	createdKey, err := client.NewKey(tpmDevice, tpm2.HandleOwner, templateRSASSA(tpm2.AlgSHA256))
	require.NoError(t, err)
	defer createdKey.Close()

	conf := TPM{
		TpmDevice: tpmDevice,
		Key:       createdKey,
	}

	tpm, err := NewTPMCrypto(&conf)
	require.NoError(t, err)

	hash := crypto.SHA256.New()
	hash.Write([]byte("test digest"))
	digest := hash.Sum(nil)

	signature, err := tpm.Sign(tpmDevice, digest, nil)
	require.NoError(t, err)

	pubKey, ok := createdKey.PublicKey().(*rsa.PublicKey)
	require.True(t, ok)

	err = rsa.VerifyPKCS1v15(pubKey, crypto.SHA256, digest, signature)
	require.NoError(t, err)
}

func TestTPMSignRSAFail(t *testing.T) {
	tpmDevice, err := simulator.Get()
	require.NoError(t, err)
	defer tpmDevice.Close()

	createdKey, err := client.NewKey(tpmDevice, tpm2.HandleOwner, templateRSASSA(tpm2.AlgSHA256))
	require.NoError(t, err)
	defer createdKey.Close()

	conf := TPM{
		TpmDevice: tpmDevice,
		Key:       createdKey,
	}

	tpm, err := NewTPMCrypto(&conf)
	require.NoError(t, err)

	hash := crypto.SHA256.New()
	hash.Write([]byte("test digest"))
	digest := hash.Sum(nil)

	signature, err := tpm.Sign(tpmDevice, digest, nil)
	require.NoError(t, err)

	pubKey, ok := createdKey.PublicKey().(*rsa.PublicKey)
	require.True(t, ok)

	err = rsa.VerifyPKCS1v15(pubKey, crypto.SHA256, []byte("another test digest"), signature)
	require.Error(t, err)
}

func TestTPMSignRSAPSS(t *testing.T) {
	tpmDevice, err := simulator.Get()
	require.NoError(t, err)
	defer tpmDevice.Close()

	createdKey, err := client.NewKey(tpmDevice, tpm2.HandleOwner, templateRSAPSS(tpm2.AlgSHA256))
	require.NoError(t, err)
	defer createdKey.Close()

	conf := TPM{
		TpmDevice: tpmDevice,
		Key:       createdKey,
	}

	tpm, err := NewTPMCrypto(&conf)
	require.NoError(t, err)

	hash := crypto.SHA256.New()
	hash.Write([]byte("test digest"))
	digest := hash.Sum(nil)

	signature, err := tpm.Sign(tpmDevice, digest, nil)
	require.NoError(t, err)

	pubKey, ok := createdKey.PublicKey().(*rsa.PublicKey)
	require.True(t, ok)

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

	createdKey, err := client.NewKey(tpmDevice, tpm2.HandleOwner, templateECC(tpm2.AlgSHA256))
	require.NoError(t, err)
	defer createdKey.Close()

	conf := TPM{
		TpmDevice: tpmDevice,
		Key:       createdKey,
	}

	tpm, err := NewTPMCrypto(&conf)
	require.NoError(t, err)

	hash := crypto.SHA256.New()
	hash.Write([]byte("test digest"))
	digest := hash.Sum(nil)

	signature, err := tpm.Sign(tpmDevice, digest, nil)
	require.NoError(t, err)

	pubKey, ok := createdKey.PublicKey().(*ecdsa.PublicKey)
	require.True(t, ok)

	ok = ecdsa.VerifyASN1(pubKey, digest[:], signature)
	require.True(t, ok)
}

func TestTPMSignECCRAW(t *testing.T) {
	tpmDevice, err := simulator.Get()
	require.NoError(t, err)
	defer tpmDevice.Close()

	createdKey, err := client.NewKey(tpmDevice, tpm2.HandleOwner, templateECC(tpm2.AlgSHA256))
	require.NoError(t, err)
	defer createdKey.Close()

	conf := TPM{
		TpmDevice:    tpmDevice,
		Key:          createdKey,
		ECCRawOutput: true,
	}

	tpm, err := NewTPMCrypto(&conf)
	require.NoError(t, err)

	hash := crypto.SHA256.New()
	hash.Write([]byte("test digest"))
	digest := hash.Sum(nil)

	signature, err := tpm.Sign(tpmDevice, digest, nil)
	require.NoError(t, err)

	pubKey, ok := createdKey.PublicKey().(*ecdsa.PublicKey)
	require.True(t, ok)

	curveBits := pubKey.Curve.Params().BitSize
	keyBytes := curveBits / 8
	if curveBits%8 > 0 {
		keyBytes += 1
	}

	x := big.NewInt(0).SetBytes(signature[:keyBytes])
	y := big.NewInt(0).SetBytes(signature[keyBytes:])

	ok = ecdsa.Verify(pubKey, digest[:], x, y)
	require.True(t, ok)
}

func TestTPMSignPolicy(t *testing.T) {
	tpmDevice, err := simulator.Get()
	require.NoError(t, err)
	defer tpmDevice.Close()

	s, err := client.NewPCRSession(tpmDevice, tpm2.PCRSelection{tpm2.AlgSHA256, []int{0}})
	require.NoError(t, err)
	ac, err := s.Auth()
	require.NoError(t, err)

	sessionTemplate := templateRSASSA(tpm2.AlgSHA256)
	sessionTemplate.AuthPolicy = ac.Auth

	createdKey, err := client.NewKey(tpmDevice, tpm2.HandleOwner, sessionTemplate)
	require.NoError(t, err)
	defer createdKey.Close()

	conf := TPM{
		TpmDevice: tpmDevice,
		Key:       createdKey,
	}

	tpm, err := NewTPMCrypto(&conf)
	require.NoError(t, err)

	hash := crypto.SHA256.New()
	hash.Write([]byte("test digest"))
	digest := hash.Sum(nil)

	signature, err := tpm.Sign(tpmDevice, digest, nil)
	require.NoError(t, err)

	pubKey, ok := createdKey.PublicKey().(*rsa.PublicKey)
	require.True(t, ok)

	err = rsa.VerifyPKCS1v15(pubKey, crypto.SHA256, digest, signature)
	require.NoError(t, err)
}

func TestTPMSignPolicyFail(t *testing.T) {
	tpmDevice, err := simulator.Get()
	require.NoError(t, err)
	defer tpmDevice.Close()

	pcr := 23

	s, err := client.NewPCRSession(tpmDevice, tpm2.PCRSelection{tpm2.AlgSHA256, []int{pcr}})
	require.NoError(t, err)
	ac, err := s.Auth()
	require.NoError(t, err)

	sessionTemplate := templateRSASSA(tpm2.AlgSHA256)
	sessionTemplate.AuthPolicy = ac.Auth

	createdKey, err := client.NewKey(tpmDevice, tpm2.HandleOwner, sessionTemplate)
	require.NoError(t, err)
	defer createdKey.Close()

	pcrval, err := tpm2.ReadPCR(tpmDevice, pcr, tpm2.AlgSHA256)
	require.NoError(t, err)

	pcrToExtend := tpmutil.Handle(pcr)

	err = tpm2.PCRExtend(tpmDevice, pcrToExtend, tpm2.AlgSHA256, pcrval, "")
	require.NoError(t, err)

	ps, err := client.NewPCRSession(tpmDevice, tpm2.PCRSelection{tpm2.AlgSHA256, []int{pcr}})
	require.NoError(t, err)

	loadedKey, err := client.LoadCachedKey(tpmDevice, createdKey.Handle(), ps)
	require.NoError(t, err)
	defer loadedKey.Close()

	conf := TPM{
		TpmDevice: tpmDevice,
		Key:       loadedKey,
	}

	tpm, err := NewTPMCrypto(&conf)
	require.NoError(t, err)

	hash := crypto.SHA256.New()
	hash.Write([]byte("test digest"))
	digest := hash.Sum(nil)

	_, err = tpm.Sign(tpmDevice, digest, nil)
	require.Error(t, err)

}
