# Lab Vault (W07-G2-01): file storage, so the bundle signing key survives
# lab restarts; plain HTTP inside the compose network only.
storage "file" {
  path = "/vault/file"
}
listener "tcp" {
  address     = "0.0.0.0:8200"
  tls_disable = true
}
api_addr      = "http://vault:8200"
disable_mlock = true
ui            = false
