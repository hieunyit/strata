# ngx_http_strata_module

Connector NGINX cho libstrata. Thiết kế: `docs/design/nginx-module.md`.

```bash
deploy/dev/run.sh make nginx NGINX_VERSION=1.30.5       # build nginx + module
deploy/dev/run.sh make test-nginx NGINX_VERSION=1.30.5  # Test::Nginx
deploy/dev/run.sh make nginx-asan test-nginx-asan    # ASan + UBSan
deploy/dev/run.sh make test-nginx-valgrind           # Valgrind memcheck (chậm)
```

Bundle (giai đoạn stub): master mmap `<strata_bundle_dir>/current.sbn` lúc đọc cấu hình; file phải bắt đầu bằng `SBN0`. `strata_bundle_pubkey` là file 32 byte thô.
