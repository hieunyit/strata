Nhiệm vụ: H6 · diễn tập mạng lab thật, chưa thay thế toàn game day
Nhánh: codex/h6-network-evidence; base: codex/m3-rate-measurements.

Đã chạy đúng 3 test có tên dưới đây, không skip, trong Docker dev cpuset 6-10, network host, mount Docker socket để test tạo container riêng; không đụng staging/production hoặc lab đang chạy của phiên khác:

`cd tests/e2e; go test -race -count=1 -timeout 12m -v -run '^(TestEventsSurviveNetworkFaults|TestBundleRolloutSurvivesNetworkFaults|TestNetworkOutageHeals)$' .`

- TestNetworkOutageHeals: cắt link thật qua Toxiproxy **5 phút** mặc định; node offline, nối lại tự online và command diagnostics hoạt động. PASS 370.75s.
- TestEventsSurviveNetworkFaults: agent process thật/mTLS stream, socket producer gửi 100 event khi cắt/nối hai lần và reset kết nối; tất cả được nhận, store có đúng 100 event. PASS 16.63s. Store event ở harness là MockEventStore; đây không phải chứng cứ ClickHouse EXACTLY ONCE, không phải chain từ NGINX.
- TestBundleRolloutSurvivesNetworkFaults: latency/slicer và cắt giữa download, agent tiếp tục nhận, verify chữ ký và activate bundle 4.160 byte; control file đúng version. PASS 20.96s. Bundle/compiler là fixture của test rollout, không phải full pack hay proof replay.

Package PASS 409.524s; output thật lưu ở h6-network-drills/output.txt. Có cảnh báo cleanup pool closed sau khi rollout xong; không có test/race failure. Resource test có tên riêng và cleanup của test đã chạy. Chưa thực hiện đủ các lỗi của game day (tắt process control plane/agent, corrupt bundle, panic với traffic NGINX liên tục và metrics). Không dùng kết quả ba test độc lập để tuyên bố đủ năm fault hoặc SLO production.
