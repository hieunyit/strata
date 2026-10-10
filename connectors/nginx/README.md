# ngx_http_strata_module

Connector NGINX cho libstrata. Thiết kế: `docs/design/nginx-module.md`.

```bash
deploy/dev/run.sh make nginx NGINX_VERSION=1.30.5       # build nginx + module
deploy/dev/run.sh make test-nginx NGINX_VERSION=1.30.5  # Test::Nginx
deploy/dev/run.sh make nginx-asan test-nginx-asan    # ASan + UBSan
deploy/dev/run.sh make test-nginx-valgrind           # Valgrind memcheck (chậm)
```

Bundle: master đọc `strata_control_file` để biết file bundle hiện hành trong `strata_bundle_dir` rồi mmap; worker theo dõi generation của control file và nạp bundle mới trong thread pool `default` (hot reload, không cần `nginx -s reload`). Định dạng control file và bundle: `docs/design/control-file.md`. `strata_bundle_pubkey` là file khóa công khai Ed25519 32 byte thô. Tạo khóa, bundle và control file cho môi trường thử: `target/release/mkbundle` (xem `engine/tools/mkbundle`).
