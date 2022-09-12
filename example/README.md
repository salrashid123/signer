



### KMS

Create keys

```bash
gcloud kms keyrings create kr  --location=us-central1

gcloud kms keys create s --keyring=kr --purpose=asymmetric-signing --location=us-central1 --default-algorithm=rsa-sign-pkcs1-2048-sha256
```


### TPM


example usage generates a new TPM unrestricted RSA key and sign,verify some data.

you can also use `TPM2_TOOLS` to import an external RSA key and seal it to handle

if you want to generate a key with `tpm2_tools` and make it persistent, 

```bash
tpm2_createprimary -C o -c primary.ctx

tpm2_import -C primary.ctx -G rsa -i client.key -u key.pub -r key.priv
tpm2_load  -C primary.ctx -u key.pub -r key.priv -c key.ctx
tpm2_evictcontrol -C o -c  0x81010002
tpm2_evictcontrol -C o -c key.ctx 0x81010002
```

### Vault

```bash
  (add to /etc/hosts)
    127.0.0.1 vault.domain.com server.domain.com

vault server -config=server.conf 

export export VAULT_ADDR='https://vault.domain.com:8200'
export VAULT_CACERT=/path/to/certs/ca/tls-ca.crt

vault operator init

export VAULT_TOKEN=<tokenfrominit>
vault  operator unseal


# new window, copy over the vault token value for admin stuff

export VAULT_TOKEN=s.x6....

vault secrets enable pki

vault write pki/config/urls \
    issuing_certificates="https://vault.domain.com:8200/v1/pki/ca" \
    crl_distribution_points="http://vault.domain.com:8200/v1/pki/crl"

vault write pki/root/generate/internal  common_name=yourdomain.com  ttl=8760h

vault write pki/config/urls issuing_certificates="https://vault.domain.com:8200/v1/pki/ca"  crl_distribution_points="https://vault.domain.com:8200/v1/pki/crl"

vault write pki/roles/domain-dot-com \
    allowed_domains=domain.com \
    allow_subdomains=true \
    max_ttl=72h

vault policy write pki-policy-client pki_client.hcl

# ceate a new vault token thats authorized to use the certo
vault token create -policy=pki-policy-client

        Key                  Value
        ---                  -----
        token                s.ix6LJ3YEphwoxD77HBAK41sy
        token_accessor       8On359bbVkF8U55UkGhMOXMR
        token_duration       768h
        token_renewable      true
        token_policies       ["default" "pki-policy-client"]
        identity_policies    []
        policies             ["default" "pki-policy-client"]

```

copy the vault token value into main.go

```golang
	r, err := salvault.NewVaultCrypto(&salvault.Vault{
		CertCN:             "client.domain.com",
		VaultToken:         "s.ix6LJ3YEphwoxD77HBAK41sy",
		VaultPath:          "pki/issue/domain-dot-com",
		VaultCAcert:        "/path/to/certs/ca/tls-ca.crt",
		VaultAddr:          "https://vault.yourdomain.com:8200",
		SignatureAlgorithm: x509.SHA256WithRSA,
	})
```