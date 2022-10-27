path "auth/token/lookup-self" {
  capabilities = ["read"]
}

path "auth/token/renew" {
  capabilities = ["update", "create"]
}

path "transit/keys/key1" {
  capabilities = ["read"]
}

path "transit/sign/key1" {
  capabilities = ["create",  "update"]
}

path "transit/verify/key1" {
  capabilities = ["create", "update"]
}