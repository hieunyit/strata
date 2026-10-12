# fuzz — cargo-fuzz targets (libFuzzer, stable rustc qua sancov)

Chạy trong image dev: `engine/fuzz/run.sh <giây> [targets...]`. Crash rơi vào
`build/fuzz/<target>/artifacts/`.

Targets: `sqli`, `xss`, `guard_chunks`, `response_tx`, `bodies`, `body_eval`,
`event_encode`, `budget_eval`, và **`ffi`** (W08-R-01: lái toàn bộ vòng đời một
transaction qua C ABI libstrata-ffi — request line, header, body chunk, response,
verdict, event, free — để bắt lỗi bộ nhớ ở biên unsafe).

`STRATA_FUZZ_ASAN=1` build với AddressSanitizer (nightly `-Zsanitizer=address
-Zbuild-std`) để bắt lỗi bộ nhớ thay vì chỉ crash tình cờ. Bản 72 giờ của
W08-R-01 dùng cờ này.

Harness differential ở `conformance/differential/` (go-net-http vs spring).
