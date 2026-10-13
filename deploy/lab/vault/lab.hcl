# Lab Vault (W07-G2-01): file storage, so the bundle signing key survives
# lab restarts; plain HTTP inside the compose network only.
storage "file" {
  path = "/vault/file"
}
listener "tcp" {
  address     = "0.0.0.0:8200"
  tls_disable = true
  # a bundle is signed whole (Ed25519) and goes to transit/sign as base64:
  # the signature package (W09-S-01) is 13 MB, past the 1 MB JSON string
  # Vault takes by default
  max_request_size             = 67108864
  max_json_string_value_length = 67108864
}
api_addr      = "http://vault:8200"
disable_mlock = true
ui            = false
