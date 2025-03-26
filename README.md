#### crypto.Signer, implementations for Trusted Platform Modules

where private keys as embedded inside:

* `Trusted Platform Module (TPM)`

Basically, you will get a `crypto.Signer` interface where the private keys are saved on those platform.  

Use the signer to create a TLS session, sign CA/CSRs, generate signed url or just sign anything.

For example, you can use this to sign data or to generate certificates/csr or for mTLS.

- `util/certgen/`:  Library that generates a self-signed x509 certificate for the KMS and TPM based signers above
- `util/csrgen/`:  Library that generates a CSR using the key in KMS or TPM 

see the [example/](example/) folder for more information.

---

>> this library is not supported by google

---

### Usage Signer

Initialize a signer and directly use `.sign()` as shown in this sample for GCS SignedURL:

* [GCS SignedURL for KMS](https://github.com/salrashid123/kms_service_accounts)
* [GCS signedURLs and GCP Authentication with Trusted Platform Module](https://github.com/salrashid123/gcs_tpm)

### Usage TLS

* for tpm see [mTLS with TPM bound private key](https://github.com/salrashid123/go_tpm_https_embed)

### Sign/Verify PSS

see `example/sign_verify*` folders

### Sign/Verify ECC

The default output signature format for ECC based keys is ASN1 format as described in [ecdsa.SignASN1](https://pkg.go.dev/crypto/ecdsa#Sign)

If you need the raw output format, set `ECCRawOutput:       true` in the config.

See the examples folder for usage

### Usage: Generate self-signed certificate

see `util/`

```bash
go run certgen/certgen.go -cn server.domain.com
```

### Usage: Generate CSR

see `util/csrgen/`

```bash
go run certgen/certgen.go -cn server.domain.com
```

---

If you just want to issue JWT's, see

* [https://github.com/salrashid123/golang-jwt-tpm](https://github.com/salrashid123/golang-jwt-tpm)
* [https://github.com/salrashid123/golang-jwt-pkcs11](https://github.com/salrashid123/golang-jwt-pkcs11)


### TPM Signer Device management

>> **NOTE** there will be a breaking change if you are using this library for TPM based signature after `v0.8.0`.  The new structure uses the [tpm-direct](https://github.com/google/go-tpm/releases/tag/v0.9.0) API.  If you would rather use the tpm2/legacy branch, please use the signer at [v0.7.2](https://github.com/salrashid123/signer/releases/tag/v0.7.2).   Library managed device was removed (it seems tpm resource managers work well enough...I'm clearly on the fence here given the recent commits..)


  The TPM device is managed externally outside of the signer.  You have to instantiate the TPM device ReadWriteCloser and client.Key outside of the library and pass that in.

  The advantage of this is you control it opening and closing.

  ```golang
	rwc, err := OpenTPM(*tpmPath)
	rwr := transport.FromReadWriter(rwc)

	pub, err := tpm2.ReadPublic{
		ObjectHandle: tpm2.TPMHandle(*handle),
	}.Execute(rwr)

	r, err := saltpm.NewTPMCrypto(&saltpm.TPM{
		TpmDevice: rwc,
		NamedHandle: &tpm2.NamedHandle{
			Handle: tpm2.TPMHandle(*handle),
			Name:   pub.Name,
		},
	})

	s, err := r.Sign(rand.Reader, digest, crypto.SHA256)

	// close the TPM if you are done signing
	rwc.Close()

	// you need to reinitialize NewTPMCrypto if you 
	// want to sign again after closing
  ```

  
TODO use a backoff retry similar to [tpmrand](https://github.com/salrashid123/tpmrand) to prevent contention.

---



### Example Setup - TPM


example usage generates a new TPM unrestricted RSA key and sign,verify some data.


You can create the persistent handles using go-tpm or using  `tpm2_tools` and make it persistent, 

First install latest `tpm2_tools`

```bash
## install latest tpm2-tools:
####  https://github.com/salrashid123/tpm2/tree/master?tab=readme-ov-file#installing-tpm2_tools-golang
#### https://tpm2-tools.readthedocs.io/en/latest/INSTALL/
```

```bash
cd example/

## if you want to use a software TPM, 
# rm -rf /tmp/myvtpm && mkdir /tmp/myvtpm
# sudo swtpm socket --tpmstate dir=/tmp/myvtpm --tpm2 --server type=tcp,port=2321 --ctrl type=tcp,port=2322 --flags not-need-init,startup-clear

## then specify "127.0.0.1:2321"  as the TPM device path in the examples
## then for tpm2_tools, export the following var
# export TPM2TOOLS_TCTI="swtpm:port=2321"

## note if you want, the primary can be the "H2" profile from https://www.hansenpartnership.com/draft-bottomley-tpm2-keys.html#name-parent
# printf '\x00\x00' > unique.dat
# tpm2_createprimary -C o -G ecc  -g sha256  -c primary.ctx -a "fixedtpm|fixedparent|sensitivedataorigin|userwithauth|noda|restricted|decrypt" -u unique.dat


## RSA - no password
	tpm2_createprimary -C o -G rsa2048:aes128cfb -g sha256 -c primary.ctx -a 'restricted|decrypt|fixedtpm|fixedparent|sensitivedataorigin|userwithauth|noda'
	tpm2_create -G rsa2048:rsassa:null -g sha256 -u key.pub -r key.priv -C primary.ctx
	tpm2_getcap  handles-transient
	tpm2_load -C primary.ctx -u key.pub -r key.priv -c key.ctx
	tpm2_evictcontrol -C o -c key.ctx 0x81008001

### RSA - no password with PEM key file

	printf '\x00\x00' > unique.dat
	tpm2_createprimary -C o -G ecc  -g sha256  -c primary.ctx -a "fixedtpm|fixedparent|sensitivedataorigin|userwithauth|noda|restricted|decrypt" -u unique.dat

	tpm2_create -G rsa2048:rsapss:null -g sha256 -u key.pub -r key.priv -C primary.ctx  --format=pem --output=rsapss_public.pem
	tpm2_getcap  handles-transient
	tpm2_load -C primary.ctx -u key.pub -r key.priv -c key.ctx
	tpm2_encodeobject -C primary.ctx -u key.pub -r key.priv -o key.pem

## rsa-pss
	tpm2_createprimary -C o -G rsa2048:aes128cfb -g sha256 -c primary.ctx -a 'restricted|decrypt|fixedtpm|fixedparent|sensitivedataorigin|userwithauth|noda'
	tpm2_getcap  handles-transient 
	tpm2_load -C primary.ctx -u key.pub -r key.priv -c key.ctx
	tpm2_evictcontrol -C o -c key.ctx 0x81008004

## ecc
	tpm2_createprimary -C o -G rsa2048:aes128cfb -g sha256 -c primary.ctx -a 'restricted|decrypt|fixedtpm|fixedparent|sensitivedataorigin|userwithauth|noda'
	tpm2_create -G ecc:ecdsa  -g sha256  -u key.pub -r key.priv -C primary.ctx  --format=pem --output=ecc_public.pem
	tpm2_getcap  handles-transient  
	tpm2_load -C primary.ctx -u key.pub -r key.priv -c key.ctx
	tpm2_evictcontrol -C o -c key.ctx 0x81008005    

## for policyPCR

	tpm2_pcrread sha256:23
	tpm2_startauthsession -S session.dat
	tpm2_policypcr -S session.dat -l sha256:23  -L policy.dat
	tpm2_flushcontext session.dat
	tpm2_createprimary -C o -G rsa2048:aes128cfb -g sha256  -c primary.ctx -a 'restricted|decrypt|fixedtpm|fixedparent|sensitivedataorigin|userwithauth|noda'
	tpm2_create -G rsa2048:rsassa:null -g sha256 -u key.pub -r key.priv -C primary.ctx  -L policy.dat
	tpm2_getcap  handles-transient
	tpm2_load -C primary.ctx -u key.pub -r key.priv -c key.ctx
	tpm2_evictcontrol -C o -c key.ctx 0x81008006

## for policyPassword

	tpm2_createprimary -C o  -G rsa2048:aes128cfb -g sha256  -c primary.ctx -a 'restricted|decrypt|fixedtpm|fixedparent|sensitivedataorigin|userwithauth|noda'
	tpm2_create -G rsa2048:rsassa:null -p testpwd -g sha256 -u key.pub -r key.priv -C primary.ctx 
	tpm2_getcap  handles-transient
	tpm2_load -C primary.ctx -u key.pub -r key.priv -c key.ctx 
	tpm2_evictcontrol -C o -c key.ctx 0x81008007

## ===== 

cd example/

## RSA-SSA managed externally
go run sign_verify_tpm/rsassa/main.go --handle=0x81008001 --tpm-path="127.0.0.1:2321"

## RSA-PSS
go run sign_verify_tpm/rsapss/main.go --handle=0x81008004 --tpm-path="127.0.0.1:2321"

## ECC
go run sign_verify_tpm/ecc/main.go --handle=0x81008005 --tpm-path="127.0.0.1:2321"

## RSA with pcr policy
go run sign_verify_tpm/policy_pcr/main.go --handle=0x81008006 --tpm-path="127.0.0.1:2321"

## RSA with password policy
go run sign_verify_tpm/policy_password/main.go --handle=0x81008007 --tpm-path="127.0.0.1:2321"
```

Note, you can define your own policy for import too...just implement the "session" interface from the signer:

```golang
type Session interface {
	GetSession() (auth tpm2.Session, closer func() error, err error) // this supplies the session handle to the library
}
```

for example, for a PCR and [AuthPolicy](https://github.com/google/go-tpm/pull/359) enforcement (eg, a PCR and password), you can define a custom session callback

```golang
type MyPCRAndPolicyAuthValueSession struct {
	rwr      transport.TPM
	sel      []tpm2.TPMSPCRSelection
	password []byte
}

func NewPCRAndPolicyAuthValueSession(rwr transport.TPM, sel []tpm2.TPMSPCRSelection, password []byte) (MyPCRAndPolicyAuthValueSession, error) {
	return MyPCRAndPolicyAuthValueSession{rwr, sel, password}, nil
}

func (p MyPCRAndPolicyAuthValueSession) GetSession() (auth tpm2.Session, closer func() error, err error) {

	var options []tpm2.AuthOption
	options = append(options, tpm2.Auth(p.password))

	sess, closer, err := tpm2.PolicySession(p.rwr, tpm2.TPMAlgSHA256, 16, options...)
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

	_, err = tpm2.PolicyAuthValue{
		PolicySession: sess.Handle(),
	}.Execute(p.rwr)
	if err != nil {
		return nil, nil, err
	}

	return sess, closer, nil
}

```

which you can call as:

```golang
	se, err := NewPCRAndPolicyAuthValueSession(rwr, []tpm2.TPMSPCRSelection{
		{
			Hash:      tpm2.TPMAlgSHA256,
			PCRSelect: tpm2.PCClientCompatible.PCRs(uint(*pcr)),
		},
	}, []byte("testpswd"))

	rr, err := saltpm.NewTPMCrypto(&saltpm.TPM{
		TpmDevice: rwc,
		NamedHandle: &tpm2.NamedHandle{
			Handle: tpm2.TPMHandle(*handle),
			Name:   pub.Name,
		},
		AuthSession: se,
	})
```

---

