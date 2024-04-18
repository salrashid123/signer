//go:build !windows

package tpm

import (
	"crypto"
	"crypto/rsa"
	"testing"

	"github.com/google/go-tpm-tools/client"
	"github.com/google/go-tpm-tools/simulator"
	"github.com/google/go-tpm/legacy/tpm2"
	"github.com/stretchr/testify/require"
)

func TestTPMPublic(t *testing.T) {
	tpmDevice, err := simulator.Get()
	require.NoError(t, err)
	defer tpmDevice.Close()

	createdKey, err := client.NewKey(tpmDevice, tpm2.HandleNull, client.SRKTemplateRSA())
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
func templateSSA(hash tpm2.Algorithm) tpm2.Public {
	template := client.AKTemplateRSA()
	// Can't sign arbitrary data if restricted.
	template.Attributes &= ^tpm2.FlagRestricted
	template.RSAParameters.Sign.Hash = hash
	return template
}

func TestTPMSign(t *testing.T) {
	tpmDevice, err := simulator.Get()
	require.NoError(t, err)
	defer tpmDevice.Close()

	createdKey, err := client.NewKey(tpmDevice, tpm2.HandleNull, templateSSA(tpm2.AlgSHA256))
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
