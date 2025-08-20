#### crypto.Signer, implementations for Trusted Platform Modules

where private keys as embedded inside `Trusted Platform Module (TPM)`

Basically, you will get a [crypto.Signer](https://pkg.go.dev/crypto#Signer) interface for the private key. 

Use the signer to create a TLS session, sign CA/CSRs, or just sign anything.

see the [example/](example/) folder for more information.

---

>> this library is not supported by google

---

### Usage Signer

Initialize a signer and directly use `.sign()` as shown in this below and in the samples


```golang
require (
	github.com/salrashid123/signer v0.9.3
)
```

then

```golang
import (
	saltpm "github.com/salrashid123/signer/tpm"
	"github.com/google/go-tpm/tpmutil"
)

	rwc, err := tpmutil.OpenTPM(path)

	stringToSign := []byte("foo")

	h := sha256.New()
	h.Write(b)
	digest := h.Sum(nil)

	// assume the handle to the rsassa key is persistentHandle 0x81008001
	r, err := saltpm.NewTPMCrypto(&saltpm.TPM{
		TpmDevice: rwc,
		Handle:    tpm2.TPMHandle(handle),
	})

	s, err := r.Sign(rand.Reader, digest, crypto.SHA256)

	fmt.Printf("RSA Signed String: %s\n", base64.StdEncoding.EncodeToString(s))
```

* [https://pkg.go.dev/github.com/salrashid123/signer/tpm](https://pkg.go.dev/github.com/salrashid123/signer/tpm)


Please import as `go get github.com/salrashid123/signer@v0.9.3`  (or whatever is the release version)

---

### Sign/Verify

see `example/sign_verify_tpm` folder.

To use this, the key must be first created on the TPM and accessed as a PersistentHandle or TPM PEM file

You can create these keys using `go-tpm` or using  `tpm2_tools`.  The example below uses tpm2_tools but for others languages and standalone applicatoins, see [openssl tpm2 provider](https://github.com/salrashid123/tpm2?tab=readme-ov-file#tpm-based-private-key) or [tpm2genkey](https://github.com/salrashid123/tpm2genkey)

For this, install latest [tpm2_tools](https://tpm2-tools.readthedocs.io/en/latest/INSTALL/) 

```bash
cd example/

## if you want to use a software TPM, 
# rm -rf /tmp/myvtpm && mkdir /tmp/myvtpm
# swtpm socket --tpmstate dir=/tmp/myvtpm --tpm2 --server type=tcp,port=2321 --ctrl type=tcp,port=2322 --flags not-need-init,startup-clear

## then specify "127.0.0.1:2321"  as the TPM device path in the examples
## and for tpm2_tools, export the following var
# export TPM2TOOLS_TCTI="swtpm:port=2321"

## if you are using a real tpm set --tpm-path=/dev/tpmrm0

## note the primary can be the "H2" profile from https://www.hansenpartnership.com/draft-bottomley-tpm2-keys.html#name-parent
# printf '\x00\x00' > unique.dat
# tpm2_createprimary -C o -G ecc  -g sha256  -c primary.ctx -a "fixedtpm|fixedparent|sensitivedataorigin|userwithauth|noda|restricted|decrypt" -u unique.dat

## RSA - no password

	tpm2_createprimary -C o -G rsa2048:aes128cfb -g sha256 -c primary.ctx -a 'restricted|decrypt|fixedtpm|fixedparent|sensitivedataorigin|userwithauth|noda'
	tpm2_create -G rsa2048:rsassa:null -g sha256 -u key.pub -r key.priv -C primary.ctx
	tpm2_flushcontext -t && tpm2_flushcontext -s && tpm2_flushcontext -l
	tpm2_load -C primary.ctx -u key.pub -r key.priv -c key.ctx
	tpm2_evictcontrol -C o -c key.ctx 0x81008001

go run sign_verify_tpm/rsassa/main.go --tpm-path="127.0.0.1:2321" --handle 0x81008001


### RSA - no password with PEM key file

	printf '\x00\x00' > unique.dat
	tpm2_createprimary -C o -G ecc  -g sha256  -c primary.ctx -a "fixedtpm|fixedparent|sensitivedataorigin|userwithauth|noda|restricted|decrypt" -u unique.dat

	tpm2_create -G rsa2048:rsapss:null -g sha256 -u key.pub -r key.priv -C primary.ctx  --format=pem --output=rsapss_public.pem
	tpm2_flushcontext -t && tpm2_flushcontext -s && tpm2_flushcontext -l
	tpm2_load -C primary.ctx -u key.pub -r key.priv -c key.ctx
	tpm2_encodeobject -C primary.ctx -u key.pub -r key.priv -o key.pem

go run sign_verify_tpm/keyfile/main.go --tpm-path="127.0.0.1:2321" -pemFile /tmp/key.pem

## rsa-pss

	tpm2_createprimary -C o -G rsa2048:aes128cfb -g sha256 -c primary.ctx -a 'restricted|decrypt|fixedtpm|fixedparent|sensitivedataorigin|userwithauth|noda'
	tpm2_create -G rsa2048:rsapss:null -g sha256 -u key.pub -r key.priv -C primary.ctx
	tpm2_flushcontext -t && tpm2_flushcontext -s && tpm2_flushcontext -l
	tpm2_load -C primary.ctx -u key.pub -r key.priv -c key.ctx
	tpm2_evictcontrol -C o -c key.ctx 0x81008004

go run sign_verify_tpm/rsapss/main.go --tpm-path="127.0.0.1:2321" --handle 0x81008004

## ecc

	tpm2_createprimary -C o -G rsa2048:aes128cfb -g sha256 -c primary.ctx -a 'restricted|decrypt|fixedtpm|fixedparent|sensitivedataorigin|userwithauth|noda'
	tpm2_create -G ecc:ecdsa  -g sha256  -u key.pub -r key.priv -C primary.ctx  --format=pem --output=ecc_public.pem
	tpm2_flushcontext -t && tpm2_flushcontext -s && tpm2_flushcontext -l
	tpm2_load -C primary.ctx -u key.pub -r key.priv -c key.ctx
	tpm2_evictcontrol -C o -c key.ctx 0x81008005    

go run sign_verify_tpm/ecc/main.go --tpm-path="127.0.0.1:2321" --handle 0x81008005

## for policyPCR

	tpm2_pcrread sha256:23
	tpm2_startauthsession -S session.dat
	tpm2_policypcr -S session.dat -l sha256:23  -L policy.dat
	tpm2_flushcontext session.dat
	tpm2_flushcontext -t && tpm2_flushcontext -s && tpm2_flushcontext -l
	tpm2_createprimary -C o -G rsa2048:aes128cfb -g sha256  -c primary.ctx -a 'restricted|decrypt|fixedtpm|fixedparent|sensitivedataorigin|userwithauth|noda'
	tpm2_create -G rsa2048:rsassa:null -g sha256 -u key.pub -r key.priv -C primary.ctx  -L policy.dat
	tpm2_flushcontext -t && tpm2_flushcontext -s && tpm2_flushcontext -l
	tpm2_load -C primary.ctx -u key.pub -r key.priv -c key.ctx
	tpm2_evictcontrol -C o -c key.ctx 0x81008006

go run sign_verify_tpm/policy_pcr/main.go --handle=0x81008006 --tpm-path="127.0.0.1:2321"

## for password

	tpm2_createprimary -C o  -G rsa2048:aes128cfb -g sha256  -c primary.ctx -a 'restricted|decrypt|fixedtpm|fixedparent|sensitivedataorigin|userwithauth|noda'
	tpm2_create -G rsa2048:rsassa:null -p testpwd -g sha256 -u key.pub -r key.priv -C primary.ctx 
	tpm2_flushcontext -t && tpm2_flushcontext -s && tpm2_flushcontext -l
	tpm2_load -C primary.ctx -u key.pub -r key.priv -c key.ctx 
	tpm2_evictcontrol -C o -c key.ctx 0x81008007

go run sign_verify_tpm/password/main.go --handle=0x81008007 --tpm-path="127.0.0.1:2321"


## for policyassword

	tpm2_createprimary -C o  -G rsa2048:aes128cfb -g sha256  -c primary.ctx -a 'restricted|decrypt|fixedtpm|fixedparent|sensitivedataorigin|userwithauth|noda'

	tpm2_startauthsession -S session.dat
	tpm2_policypassword -S session.dat -L policy.dat
	tpm2_flushcontext session.dat

	tpm2_create -G rsa2048:rsassa:null -p testpwd -g sha256 -u key.pub -r key.priv -C primary.ctx  -L policy.dat
	tpm2_flushcontext -t && tpm2_flushcontext -s && tpm2_flushcontext -l
	tpm2_load -C primary.ctx -u key.pub -r key.priv -c key.ctx 
	tpm2_evictcontrol -C o -c key.ctx 0x81008008

go run sign_verify_tpm/password/main.go --handle=0x81008007 --tpm-path="127.0.0.1:2321"

```


### Usage TLS

* for tpm see [mTLS with TPM bound private key](https://github.com/salrashid123/go_tpm_https_embed)

### Sign/Verify ECC

The default output signature format for ECC based keys is ASN1 format as described in [ecdsa.SignASN1](https://pkg.go.dev/crypto/ecdsa#Sign)

If you need the raw output format, set `ECCRawOutput:  true` in the config.

See the examples folder for usage

### Usage: Generate CSR

The following will generate a TPM based key and then issue a CSR against it.

```bash
### create key, rsassa
 # using H2 template ( https://gist.github.com/salrashid123/9822b151ebb66f4083c5f71fd4cdbe40 )
printf '\x00\x00' > unique.dat
tpm2_createprimary -C o -G ecc  -g sha256 \
   -c primary.ctx -a "fixedtpm|fixedparent|sensitivedataorigin|userwithauth|noda|restricted|decrypt" -u unique.dat
   
 tpm2_create -G rsa2048:rsassa:null -g sha256 -u key.pub -r key.priv -C primary.ctx
 tpm2_flushcontext -t
 tpm2_load -C primary.ctx -u key.pub -r key.priv -c key.ctx
 tpm2_evictcontrol -C o -c key.ctx 0x81008001
 tpm2_flushcontext -t
 tpm2_encodeobject -C primary.ctx -u key.pub -r key.priv -o private.pem

cd util/csrgen/
go run csrgen/csrgen.go -cn server.domain.com  --persistentHandle 0x81008001
```

### Usage: Generate self-signed certificate

The following will generate a key on the tpm, then use that RSA key to issue a CSR and then sign that CSR with by itself to get an x509.

You can ofcourse modify it to just sign any csr with a TPM backed key


```bash
 # using H2 template ( https://gist.github.com/salrashid123/9822b151ebb66f4083c5f71fd4cdbe40 )
printf '\x00\x00' > unique.dat
tpm2_createprimary -C o -G ecc  -g sha256 \
   -c primary.ctx -a "fixedtpm|fixedparent|sensitivedataorigin|userwithauth|noda|restricted|decrypt" -u unique.dat

 tpm2_create -G rsa2048:rsassa:null -g sha256 -u key.pub -r key.priv -C primary.ctx
 tpm2_flushcontext -t
 tpm2_load -C primary.ctx -u key.pub -r key.priv -c key.ctx
 tpm2_evictcontrol -C o -c key.ctx 0x81008002
 tpm2_flushcontext -t
 tpm2_encodeobject -C primary.ctx -u key.pub -r key.priv -o private.pem

go run certgen/certgen.go -cn server.domain.com --persistentHandle 0x81008002
```

---

If you just want to issue JWT's, see

* [https://github.com/salrashid123/golang-jwt-tpm](https://github.com/salrashid123/golang-jwt-tpm)
* [https://github.com/salrashid123/golang-jwt-pkcs11](https://github.com/salrashid123/golang-jwt-pkcs11)

or real random:

* [TPM backed crypto/rand Reader](https://github.com/salrashid123/tpmrand)

---

#### Keys with Auth Policy

If the key is setup with an AuthPolicy (eg, a policy that requires a passphrase or a predefined PCR values to exist), you can specify those in code or define your own


##### PasswordAuth

If the key requires a password, initialize a `NewPasswordAuthSession`

```golang
	se, err := saltpm.NewPasswordAuthSession(rwr, []byte(*keyPass), 0)

	rr, err := saltpm.NewTPMCrypto(&saltpm.TPM{
		TpmDevice:   rwc,
		Handle:      tpm2.TPMHandle(*handle),
		AuthSession: se,
	})
```

##### PCRPolicy

If the key requires a password, initialize a `NewPCRSession`

```golang
	se, err := saltpm.NewPCRSession(rwr, []tpm2.TPMSPCRSelection{
		{
			Hash:      tpm2.TPMAlgSHA256,
			PCRSelect: tpm2.PCClientCompatible.PCRs(uint(23)),
		},
	}, tpm2.TPM2BDigest{}, 0)

	rr, err := saltpm.NewTPMCrypto(&saltpm.TPM{
		TpmDevice:   rwc,
		Handle:      tpm2.TPMHandle(*handle),
		AuthSession: se,
	})

```

##### CustomPolicy

Note, you can define your own policy for import too...just implement the "session" interface from the signer:

```golang
type Session interface {
	GetSession() (auth tpm2.Session, closer func() error, err error) // this supplies the session handle to the library
}
```

for example, for a PCR and [AuthPolicy](https://github.com/google/go-tpm/pull/359) enforcement (eg, a PCR and password), you can define a custom session callback.

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
		return nil, closer, err
	}

	_, err = tpm2.PolicyAuthValue{
		PolicySession: sess.Handle(),
	}.Execute(p.rwr)
	if err != nil {
		return nil, closer, err
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
		Handle:    tpm2.TPMHandle(*handle*),
		AuthSession: se,
	})
```

---

