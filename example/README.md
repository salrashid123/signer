



### KMS

Create keys

```bash
gcloud kms keyrings create kr  --location=us-central1

gcloud kms keys create --keyring=kr --purpose=asymmetric-signing --location=us-central1 --default-algorithm=rsa-sign-pkcs1-2048-sha256
```


### TPM


example usage generates a new TPM unrestricted RSA key and sign,verify some data.

to use, you can create a key directly which will create an RSA key and make it persistent to `0x81008000`

```bash
go run sign_verify_tpm/main.go --evict=true
```

you can also use `TPM2_TOOLS` to import an external RSA key and seal it to handle

if you want to generate a key with `tpm2_tools` and make it persistent, 

```bash

## the follwoing will create a key on the tpm and make it persistent
tpm2_createprimary -C o -c primary.ctx

tpm2_create -G rsa -u key.pub -r key.priv -C primary.ctx
tpm2_load  -C primary.ctx -u key.pub -r key.priv -c key.ctx
tpm2_evictcontrol -C o -c  0x81008004
tpm2_evictcontrol -C o -c key.ctx 0x81008004

go run sign_verify_tpm/main.go --evict=false --persistentHandle=0x81008004
```

Please note that we are persisting the handle here for easy access.  The more formal way is to save the entire chain of keys (which is a TODO)

A limitation of using persistent handles is that its limited on a TPM (typically 7 slots).  You have to evict (i.,e delete) one before loading a new one.


### Vault

```bash
  (add to /etc/hosts)
    127.0.0.1 vault.domain.com server.domain.com

cd sign_verify_vault/
mkdir -p filebackend/

vault server -config=server.conf 

export export VAULT_ADDR='https://vault.domain.com:8200'
export VAULT_CACERT=../certs/tls-ca-chain.pem

vault operator init

export VAULT_TOKEN=<tokenfrominit>
vault  operator unseal

vault secrets enable transit

# create an rsa key
vault write -f transit/keys/key1 type='rsa-2048'

vault policy write transit-policy transit_policy.hcl

vault token create -policy=transit-policy 
    Key                  Value
    ---                  -----
    token                s.HA5jPy9J1PT1gFJdU4gFpopW


# in a new window still inside sign_verify_vault folder, copty the token over
export export VAULT_ADDR='https://vault.domain.com:8200'
export VAULT_CACERT=../certs/tls-ca-chain.pem
export VAULT_TOKEN=s.HA5jPy9J1PT1gFJdU4gFpopW


export PUBLIC_KEY=`vault read -format=json transit/keys/key1 | jq -r '.data.keys."1".public_key'`
echo $PUBLIC_KEY
```


### PKCS1v15

```bash
vault write transit/sign/key1 input=Zm9v signature_algorithm=pkcs1v15 hash_algorithm=sha2-256 

    Key            Value
    ---            -----
    key_version    1
    signature      vault:v1:goom/u9h79moyVtH0nZfclX0w/Ef9ZnRO8ATEP81RqBeicne5+1Rab0Hb4AnfQ4csKab8Ar4Q/5mCFUMtlOaOHPy7IA3lnDmR069dgScmiPodRx0yfnZwRm2QXnCiSfqgylMEigZGhwyteg4vOSmTBRKKT0cLd7iXaCLr0XPMGNXloiE+yDXLkdvRroYTEiIzDRF6j9PYTBnsjqBln6yl5Bk54K3ugql5k/oQmfSfWyKqASYDjpNrGlH9k8kDT344lwMAPGZgnzpymgfD03kDj3Rbq7UBOgAo2XyX/SOw00HK339FlkyZeubOJBHE8BwEKRg1AoiFsVq9UdD6DrFkA==


vault write transit/verify/key1  input=Zm9v signature=vault:v1:goom/u9h79moyVtH0nZfclX0w/Ef9ZnRO8ATEP81RqBeicne5+1Rab0Hb4AnfQ4csKab8Ar4Q/5mCFUMtlOaOHPy7IA3lnDmR069dgScmiPodRx0yfnZwRm2QXnCiSfqgylMEigZGhwyteg4vOSmTBRKKT0cLd7iXaCLr0XPMGNXloiE+yDXLkdvRroYTEiIzDRF6j9PYTBnsjqBln6yl5Bk54K3ugql5k/oQmfSfWyKqASYDjpNrGlH9k8kDT344lwMAPGZgnzpymgfD03kDj3Rbq7UBOgAo2XyX/SOw00HK339FlkyZeubOJBHE8BwEKRg1AoiFsVq9UdD6DrFkA== signature_algorithm=pkcs1v15 hash_algorithm=sha2-256 

  Key      Value
  ---      -----
  valid    true
```

### PSS

```bash
$ vault write transit/sign/key1 input=Zm9v signature_algorithm=pss hash_algorithm=sha2-256 
    Key            Value
    ---            -----
    key_version    1
    signature      vault:v1:PfhjgTYM6JlgibDqRN5JhIEnwZHWzEC5nHNEIHcq1koPkGxbxcs+cJhF45Usf08BvbzPeH5VtLpTUT4m4zQ39v+Nyq1HuskruC2G6rLjGCQuK5CBnHmM5VuuyOVxbIisY311o2LBcp8oN3zNbjIFrDPQOeR+I6aUaINPhmmAZl2cRBuGnlDSWKZoEmax6Llzcmf9+Rj9c1NndEPOVTK7VRxkquaHWTyecfzFNxu3V/fLoBc8NnZ9eiaDBvpAc3YE7T0NVewkzn64eD6lmPCUSDGL6ws3hx/JCmlH+Vrsfh3mHtT/s1hx5Aqr/fLrq7jMKMOY8TK/TPjrkkYkK/aCPA==


$ vault write transit/verify/key1  input=Zm9v signature=vault:v1:PfhjgTYM6JlgibDqRN5JhIEnwZHWzEC5nHNEIHcq1koPkGxbxcs+cJhF45Usf08BvbzPeH5VtLpTUT4m4zQ39v+Nyq1HuskruC2G6rLjGCQuK5CBnHmM5VuuyOVxbIisY311o2LBcp8oN3zNbjIFrDPQOeR+I6aUaINPhmmAZl2cRBuGnlDSWKZoEmax6Llzcmf9+Rj9c1NndEPOVTK7VRxkquaHWTyecfzFNxu3V/fLoBc8NnZ9eiaDBvpAc3YE7T0NVewkzn64eD6lmPCUSDGL6ws3hx/JCmlH+Vrsfh3mHtT/s1hx5Aqr/fLrq7jMKMOY8TK/TPjrkkYkK/aCPA== signature_algorithm=pss hash_algorithm=sha2-256 
    Key      Value
    ---      -----
    valid    true
```


### test

edit `main.go`, set

```golang
	r, err := salvault.NewVaultCrypto(&salvault.Vault{
		VaultToken:         "s.HA5jPy9J1PT1gFJdU4gFpopW",
```

see

```
Data to sign SHA256WithRSA foo
Signed String: goom/u9h79moyVtH0nZfclX0w/Ef9ZnRO8ATEP81RqBeicne5+1Rab0Hb4AnfQ4csKab8Ar4Q/5mCFUMtlOaOHPy7IA3lnDmR069dgScmiPodRx0yfnZwRm2QXnCiSfqgylMEigZGhwyteg4vOSmTBRKKT0cLd7iXaCLr0XPMGNXloiE+yDXLkdvRroYTEiIzDRF6j9PYTBnsjqBln6yl5Bk54K3ugql5k/oQmfSfWyKqASYDjpNrGlH9k8kDT344lwMAPGZgnzpymgfD03kDj3Rbq7UBOgAo2XyX/SOw00HK339FlkyZeubOJBHE8BwEKRg1AoiFsVq9UdD6DrFkA==
Signed String SHA256WithRSA verified

Signed SHA256WithRSAPSS String: YlgIWHE6vnNjg1iV+QZeCbDlDpR0IKbWAfdzTRgq8vjrN5LjjdY+x7bucQKk+YWxnoNr3z3fLISBt8QibKryge3ZMRK+mjwILORXpWNBsJva4MZvvDdco/mKwt1qZSpon+RVrgE6OTWd3tyxRexAq3x93JSEBdosdWVkpIuj3+nhKPLoLvRYr71/9kqhuZN/2ivamxnTGVu+O7m0oqQTtfuVluSCKYLmCwmobpYRP4La0diVOEJ/m/DhbDi6DOkwDmRw2I4ktYS1881/Z4egWdENysn+UalR0rhpzHeYB2aIAnvVSx9rcjmNb5N0iNrN0/F+/7eDu4ik29OukSGB5Q==
Signed String SHA256WithRSAPSS verified

```