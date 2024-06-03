



### KMS

Create keys

```bash
gcloud kms keyrings create kr  --location=us-central1

## rsa-sign-pkcs1-2048-sha256
gcloud kms keys create rskey1 --keyring=kr --purpose=asymmetric-signing --location=us-central1 --default-algorithm=rsa-sign-pkcs1-2048-sha256

## rsa-sign-pss-2048-sha256
gcloud kms keys create rskey2 --keyring=kr --purpose=asymmetric-signing --location=us-central1 --default-algorithm=rsa-sign-pss-2048-sha256

## ec-sign-p256-sha256
gcloud kms keys create ec1 --keyring=kr --purpose=asymmetric-signing --location=us-central1 --default-algorithm=ec-sign-p256-sha256
```


### TPM


example usage generates a new TPM unrestricted RSA key and sign,verify some data.


You can create the persistent handles using go-tpm or using  `tpm2_tools` and make it persistent, 

First install latest `tpm2_tools`

```bash
## install latest tpm2-tools:
####  https://github.com/salrashid123/tpm2/tree/master?tab=readme-ov-file#installing-tpm2_tools-golang
#### https://tpm2-tools.readthedocs.io/en/latest/INSTALL/

apt-get update

apt -y install   autoconf-archive   libcmocka0   libcmocka-dev   procps  \
   iproute2   build-essential   git   pkg-config   gcc   libtool   automake \
     libssl-dev   uthash-dev   autoconf   doxygen  libcurl4-openssl-dev dbus-x11 libglib2.0-dev libjson-c-dev acl

cd
git clone https://github.com/tpm2-software/tpm2-tss.git
  cd tpm2-tss
  ./bootstrap
  ./configure --with-udevrulesdir=/etc/udev/rules.d
  make -j$(nproc)
  make install
  udevadm control --reload-rules && sudo udevadm trigger
  ldconfig

cd
git clone https://github.com/tpm2-software/tpm2-tools.git
  cd tpm2-tools
  ./bootstrap
  ./configure
  make check
  make install

## install golang  
wget https://go.dev/dl/go1.22.3.linux-amd64.tar.gz
rm -rf /usr/local/go && tar -C /usr/local -xzf go1.22.3.linux-amd64.tar.gz
export PATH=$PATH:/usr/local/go/bin
```

```bash
cd example/

rm -rf /tmp/myvtpm && mkdir /tmp/myvtpm
sudo swtpm socket --tpmstate dir=/tmp/myvtpm --tpm2 --server type=tcp,port=2321 --ctrl type=tcp,port=2322 --flags not-need-init,startup-clear
export TPM2TOOLS_TCTI="swtpm:port=2321"


## RSA - no password
	tpm2_createprimary -C o -G rsa2048:aes128cfb -g sha256 -c primary.ctx -a 'restricted|decrypt|fixedtpm|fixedparent|sensitivedataorigin|userwithauth|noda'
	tpm2_create -G rsa2048:rsassa:null -g sha256 -u key.pub -r key.priv -C primary.ctx
	tpm2_flushcontext  -t
	tpm2_getcap  handles-transient
	tpm2_load -C primary.ctx -u key.pub -r key.priv -c key.ctx
	tpm2_evictcontrol -C o -c key.ctx 0x81008001
	tpm2_flushcontext  -t

## rsa-pss
	tpm2_createprimary -C o -G rsa2048:aes128cfb -g sha256 -c primary.ctx -a 'restricted|decrypt|fixedtpm|fixedparent|sensitivedataorigin|userwithauth|noda'
	tpm2_create -G rsa2048:rsapss:null -g sha256 -u key.pub -r key.priv -C primary.ctx  --format=pem --output=rsapss_public.pem
	tpm2_flushcontext  -t
	tpm2_getcap  handles-transient 
	tpm2_load -C primary.ctx -u key.pub -r key.priv -c key.ctx
	tpm2_evictcontrol -C o -c key.ctx 0x81008004
	tpm2_flushcontext  -t

## ecc
	tpm2_createprimary -C o -G rsa2048:aes128cfb -g sha256 -c primary.ctx -a 'restricted|decrypt|fixedtpm|fixedparent|sensitivedataorigin|userwithauth|noda'
	tpm2_create -G ecc:ecdsa  -g sha256  -u key.pub -r key.priv -C primary.ctx  --format=pem --output=ecc_public.pem
	tpm2_flushcontext  -t
	tpm2_getcap  handles-transient  
	tpm2_load -C primary.ctx -u key.pub -r key.priv -c key.ctx
	tpm2_evictcontrol -C o -c key.ctx 0x81008005    
	tpm2_flushcontext  -t


## for policyRSApersistentHandle

	tpm2_pcrread sha256:23
	tpm2_startauthsession -S session.dat
	tpm2_policypcr -S session.dat -l sha256:23  -L policy.dat
	tpm2_flushcontext session.dat
	tpm2_flushcontext  -t
	tpm2_createprimary -C o -G rsa2048:aes128cfb -g sha256  -c primary.ctx -a 'restricted|decrypt|fixedtpm|fixedparent|sensitivedataorigin|userwithauth|noda'
	tpm2_create -G rsa2048:rsassa:null -g sha256 -u key.pub -r key.priv -C primary.ctx  -L policy.dat
	tpm2_flushcontext  -t
	tpm2_getcap  handles-transient
	tpm2_load -C primary.ctx -u key.pub -r key.priv -c key.ctx
	tpm2_evictcontrol -C o -c key.ctx 0x81008006
	tpm2_flushcontext  -t

## ===== 

cd example/

## RSA-SSA managed externally
go run sign_verify_tpm/rsassa/main.go --handle=0x81008001

## RSA-SSA managed by library
go run sign_verify_tpm/rsassa_managed/main.go --handle=0x81008001

## RSA-PSS
go run sign_verify_tpm/rsapss/main.go --handle=0x81008004

## ECC
go run sign_verify_tpm/ecc/main.go --handle=0x81008005 

## RSA with policy
go run sign_verify_tpm/policy/main.go --handle=0x81008006
```


