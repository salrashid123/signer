#### crypto.Signer, implementations for Trusted Platform Modules

where private keys as embedded inside `Trusted Platform Module (TPM)`

Basically, you will get a [crypto.Signer](https://pkg.go.dev/crypto#Signer) interface for the private key. 

Use the signer to create a TLS session, sign CA/CSRs, or just sign anything.

see the [example/](example/) folder for more information.

---

>> this library is not supported by google



** NOTE **, this library is read-only now and has been migrated to standalone module here:


**github.com/salrashid123/tpmsigner**


the methods are the same, just import as:

```golang

import (
	"github.com/salrashid123/tpmsigner"
)

	r, err := tpmsigner.NewTPMCrypto(&tpmsigner.TPM{
		TpmDevice: rwc,
		Handle:    tpm2.TPMHandle(*handle),
	})

	s, err := r.Sign(rand.Reader, digest, crypto.SHA256)

```


(why did i migrate this? well, i completely messed up the package names/structures )


