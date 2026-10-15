# Kiến trúc Hệ thống Strata WAF — Topology C4 & Service Modeling

Tài liệu thiết kế kiến trúc toàn diện cho hệ thống tường lửa ứng dụng web **Strata WAF**, áp dụng mô hình **C4 (Context, Container, Component, Deployment)**. Tài liệu mô tả trực quan cấu trúc hệ thống, ranh giới an ninh, phân tầng trách nhiệm và các luồng dữ liệu vận hành.

---

## 1. C4 Level 1: System Context Diagram (Bối cảnh Hệ thống)

Sơ đồ ngữ cảnh thể hiện vị trí của Strata WAF trong bức tranh tổng thể của doanh nghiệp: cách người dùng, kẻ tấn công, đội ngũ vận hành SOC và các hệ thống phụ trợ bên ngoài tương tác với WAF.

```mermaid
flowchart TB
    subgraph Users ["Đối tượng Người dùng"]
        Client["Khách hàng hợp lệ\n(Web / Mobile / API Client)"]
        Attacker["Kẻ tấn công\n(Botnet / Exploit / DDoS / Scanner)"]
        SecOps["Đội ngũ An ninh mạng\n(SOC / AppSec Engineers)"]
        Admin["Quản trị viên Hệ thống\n(DevOps / SRE)"]
    end

    subgraph StrataWAF ["Hệ thống Strata WAF"]
        EdgeProxy["Strata Edge Gateway\n(NGINX + ngx_http_strata_module + libstrata)\nKiểm soát traffic thời gian thực"]
        StrataCP["Strata Control Plane & Agent\nQuản trị cấu hình, bundle, phân phối và thu thập telemetry"]
        StrataUI["Strata Web Console\nGiao diện trực quan cho SOC & Quản trị"]
    end

    subgraph InternalServices ["Hệ thống Dịch vụ Nội bộ"]
        UpstreamApps["Dịch vụ Ứng dụng Backend\n(REST / GraphQL / gRPC Microservices)"]
    end

    subgraph ExternalServices ["Hạ tầng & Dịch vụ Bổ trợ"]
        IdP["Identity Provider (OIDC / OAuth2)\n(Keycloak / Okta / Azure AD)"]
        SIEM["Hệ thống SIEM / SOC bên ngoài\n(Splunk / Elastic / OpenSearch)"]
        KMS["Hệ thống Quản lý Khóa (KMS / Vault)\nKý duyệt chính sách"]
    end

    Client -->|"Gửi request HTTPS"| EdgeProxy
    Attacker -.->|"Thăm dò, khai thác, tấn công HTTP"| EdgeProxy
    EdgeProxy -->|"Chuyển tiếp request an toàn"| UpstreamApps
    EdgeProxy -->|"Phản hồi 403 Forbidden / RST Stream khi bị chặn"| Attacker

    EdgeProxy -->|"Đẩy log vi phạm & sự kiện bảo mật"| StrataCP
    StrataCP -->|"Phân phối Bundles & Lệnh điều khiển khẩn cấp"| EdgeProxy

    SecOps -->|"Giám sát, phân tích FP, cấu hình chính sách"| StrataUI
    Admin -->|"Quản lý hạ tầng cụm, chứng chỉ, rollout"| StrataUI

    StrataUI -->|"API quản trị HTTPS"| StrataCP
    StrataCP -->|"Xác thực người dùng quản trị"| IdP
    StrataCP -->|"Tích hợp ký số bundle"| KMS
    StrataCP -->|"Xuất sự kiện bảo mật & cảnh báo"| SIEM
```

---

## 2. C4 Level 2: Container Diagram (Kiến trúc Container / Dịch vụ)

Strata được thiết kế theo kiến trúc phi tập trung, phân tách rạch ròi giữa **Data Plane (mặt phẳng dữ liệu thời gian thực)** và **Control Plane (mặt phẳng điều khiển và phân tích)** nhằm đảm bảo an toàn tuyệt đối, zero-downtime và không gây nghẽn đường truyền.

```mermaid
flowchart TB
    subgraph DataPlaneNode ["Edge Node (Data Plane)"]
        subgraph NginxProc ["NGINX Worker Process (C)"]
            NginxCore["NGINX Core\n(HTTP Processing Engine)"]
            StrataMod["ngx_http_strata_module.c\n(Connector Module C)"]
            ShmBreaker["Worker Circuit Breaker\n& Local Fallback State"]
        end

        subgraph EngineFFI ["libstrata.so (Rust Core)"]
            RustFFI["Strata C ABI FFI"]
            EngineCore["Detection & Eval Engine\n(Hyperscan, Tokenizer, Regex, DLP)"]
            CPUGuard["Cooperative CPU Budget Guard\n(Tối đa 10ms/request)"]
        end

        subgraph ShmStorage ["Shared Memory (/dev/shm)"]
            BundleShm["Active Bundle Image\n(mmap atomic pointer swap)"]
            MetricsShm["Atomic Counters\n(Requests, Blocks, Fallbacks)"]
            ControlFile["Control & Killswitch File\n(strata.ctl / disabled rules)"]
        end

        subgraph LocalAgent ["strata-agent (Go Daemon)"]
            AgentSock["Unix Datagram Listener\n(/run/strata/events.sock)"]
            Batcher["Spooler & Memory Batcher"]
            AgentFleet["Fleet Client (mTLS)\n& Bundle Manager"]
            PoissonCheck["Local Anomaly Detector\n(Poisson Error Spikes)"]
        end
    end

    subgraph ControlPlaneCluster ["Control Plane Cluster"]
        ControlPlaneAPI["strata-control-plane (Go)\n- Fleet Management Service (gRPC mTLS)\n- Policy Compiler & Signer (Ed25519)\n- Event Ingest Service\n- Replay & Anonymizer Engine\n- RBAC & LocalAuth / OIDC Handler"]
        
        WebUI["Strata Web Dashboard\n(React 18 + TypeScript + TailwindCSS + Vite)\nSPA phục vụ qua NGINX/CDN"]
    end

    subgraph StorageCluster ["Cơ sở Dữ liệu & Lưu trữ Phân tán"]
        Postgres["PostgreSQL 16+\n(Chính sách, Phiên bản, Node Enrollment, RBAC, Users)"]
        ClickHouse["ClickHouse Cluster\n(Sự kiện WAF, Block ID, Telemetry, Materialized Views)"]
        ObjectStore["MinIO / S3 Storage\n(Signature Packs, Signed Bundles, Parquet Replay Traffic)"]
    end

    %% Tương tác trong Data Plane Node
    NginxCore <-->|"HTTP Hooks (Preaccess, Body, Filter)"| StrataMod
    StrataMod <-->|"Zero-copy C ABI call"| RustFFI
    RustFFI --- EngineCore
    EngineCore --- CPUGuard
    StrataMod <-->|"Atomic read/swap"| BundleShm
    StrataMod <-->|"Atomic increment"| MetricsShm
    StrataMod <-->|"Đọc cờ khẩn cấp"| ControlFile
    StrataMod -->|"Non-blocking Datagram UDS"| AgentSock

    AgentSock --> Batcher
    Batcher --> AgentFleet
    PoissonCheck -.->|"Tự động kích hoạt Fallback khi lỗi vượt ngưỡng"| ControlFile
    AgentFleet -->|"Ghi bundle mới & cập nhật control"| BundleShm
    AgentFleet -->|"Gập nhật danh sách rule bị tắt"| ControlFile

    %% Tương tác Data Plane <-> Control Plane
    AgentFleet <==|"gRPC over mTLS (Port 8443)\n- Event Stream\n- Heartbeat & Presence\n- Bundle Pull / Push Notifications\n- Emergency Commands"|==> ControlPlaneAPI

    %% Tương tác Control Plane <-> UI & Storage
    WebUI <==|"REST HTTPS (Port 443 / 8080)\nJWT Bearer Token / Cookie"|==> ControlPlaneAPI
    ControlPlaneAPI <-->|"pgx Pool / SQL"| Postgres
    ControlPlaneAPI -->|"Batch Ingest TCP (9000/9440)"| ClickHouse
    ControlPlaneAPI <-->|"S3 API (HTTPS)"| ObjectStore
```

---

## 3. C4 Level 3: Component Diagram (Chi tiết Thành phần)

### 3.1. Thành phần NGINX Connector & Lõi Rust (`libstrata`)

```mermaid
flowchart LR
    subgraph ConnectorModule ["NGINX Connector (ngx_http_strata_module)"]
        PhaseHandler["Phase Handlers\n- PREACCESS (Header/URI)\n- ACCESS (Body Form/JSON/Multipart)\n- HEADER_FILTER (Response Status/Headers)\n- BODY_FILTER (Response DLP)\n- LOG (Metrics & Cleanups)"]
        BreakerMgr["Circuit Breaker Component\n(Theo dõi chuỗi lỗi, fail-open/closed)"]
        BundleMgr["Bundle Reloader\n(Atomic Pointer Swap, Zero-lock)"]
        EventClient["Event Socket Client\n(Non-blocking Datagram /dev/shm Buffer)"]
    end

    subgraph LibstrataRust ["libstrata Core Engine (Rust)"]
        FFILayer["FFI C Wrapper\n(strata_tx_*, catch_unwind safety)"]
        
        subgraph ParserPipeline ["Parser & Normalization Pipeline"]
            UrlDec["URL & Unicode Decoder"]
            FormParser["Form URL-Encoded Parser"]
            MultipartParser["Multipart MIME Stream Parser"]
            JsonXmlParser["JSON & XML Tree Parser"]
            B64Args["Base64 Auto-Detector & Budget Dec"]
        end

        subgraph DetectionEngine ["Detection & Evaluation Engine"]
            HSEngine["Hyperscan Multiregex Block Mode\n(Khớp hàng nghìn mẫu song song)"]
            RegexEngine["Rust Linear-time Regex Engine\n(Capture group & fallback)"]
            Operators["Operators Library\n(streq, rx, ipMatch, validateUtf8, etc.)"]
            ScoringCalc["Scoring & Anomaly Accumulator"]
            DLPScanner["Response DLP Detectors\n(CCCD, PAN CreditCard, JWT, DB Errors)"]
        end

        BudgetManager["CPU Budget Checkpoints\n(Giới hạn tối đa 10ms, kiểm tra hợp tác)"]
    end

    PhaseHandler -->|"Trích xuất pointer + length"| FFILayer
    BreakerMgr -.->|"Ngắt kiểm tra khi lỗi liên tiếp"| PhaseHandler
    BundleMgr -->|"Cung cấp con trỏ bộ nhớ bundle"| FFILayer
    PhaseHandler -->|"Gửi sự kiện khi có vi phạm"| EventClient

    FFILayer --> ParserPipeline
    ParserPipeline --> DetectionEngine
    DetectionEngine <--> BudgetManager
    DetectionEngine -->|"Tính điểm & Ra quyết định (Pass/Block/Shadow)"| FFILayer
```

### 3.2. Thành phần Strata Agent (`strata-agent`)

```mermaid
flowchart TD
    subgraph StrataAgentCore ["Strata Agent Architecture (Go)"]
        UDSListener["Unix Domain Socket Listener\n(/run/strata/events.sock, buffers: 8192)"]
        
        subgraph EventProcessing ["Event Ingest Pipeline"]
            Deduplicator["Event Deduplicator & Rate Limiter"]
            DiskSpooler["Disk Spooler (Fallback khi mất mạng)\n(/var/spool/strata-agent/queue.db)"]
            MemBatcher["In-Memory Chunk Batcher\n(Tối đa 1.000 events hoặc 500ms)"]
        end

        subgraph FleetManager ["Fleet & Lifecycle Manager"]
            EnrollmentClient["Auto-Enrollment Client\n(mTLS CSR, Token Exchange)"]
            HeartbeatPresence["Heartbeat & Health Reporter\n(Báo cáo CPU, Shm, Version, Drop rates)"]
            BundleSync["Bundle Synchronizer\n(Kiểm tra chữ ký Ed25519, ghi file atomic)"]
            CommandDispatcher["Emergency Command Dispatcher\n(DisableRules, ForceShadow, Rollback)"]
        end

        subgraph LocalWatchdog ["Local Watchdog & Anomaly Engine"]
            PoissonDetector["Poisson Anomaly Statistical Test\n(Theo dõi tỉ lệ spike 5xx/crash)"]
            ShmMetricsCollector["Shared Memory Metrics Reader\n(Đọc trực tiếp /dev/shm/strata_metrics)"]
            ControlWriter["Control File Writer\n(Ghi trạng thái fallback xuống strata.ctl)"]
        end
    end

    UDSListener --> Deduplicator
    Deduplicator --> MemBatcher
    MemBatcher -->|"Mất mạng"| DiskSpooler
    DiskSpooler -->|"Hồi phục"| MemBatcher
    
    ShmMetricsCollector --> PoissonDetector
    PoissonDetector -->|"Phát hiện bất thường nghiêm trọng"| ControlWriter
    CommandDispatcher --> ControlWriter

    FleetManager <==|"gRPC Stream mTLS"|==> RemoteCP["Strata Control Plane"]
    MemBatcher -->|"Đẩy Batch Events"| RemoteCP
```

### 3.3. Thành phần Strata Control Plane (`control-plane`)

```mermaid
flowchart TB
    subgraph ControlPlaneArch ["Strata Control Plane Architecture"]
        subgraph APIGateway ["API & Ingress Layer"]
            HTTPRouter["HTTP / REST API Router (Chi/Mux)"]
            GRPCServer["gRPC Fleet Management Server"]
            AuthMiddleware["Auth & RBAC Middleware\n(OIDC Token Validator & LocalAuth JWT)"]
            AuditLogger["Security Audit Logger"]
        end

        subgraph CoreServices ["Core Business Services"]
            PolicySvc["Policy Management Service\n- Versioning & Draft Engine\n- 4-Eyes Approval Workflow\n- Canary Distribution Allocator"]
            CompilerSvc["Bundle Compiler & Signer\n- JSON/YAML IR Validator\n- Hyperscan DB Serializer\n- Ed25519 Cryptographic Signer"]
            FleetSvc["Fleet Coordination Service\n- Node Registry & Heartbeat Tracking\n- Emergency Broadcast Coordinator"]
            EventIngestSvc["Event Ingestion Service\n- High-throughput Validation\n- Event Context Enricher\n- ClickHouse Buffer Flusher"]
            ReplaySvc["Replay & Validation Service\n- Parquet Sample Loader\n- Traffic Anonymizer (PII Stripping)\n- Differential Test Engine"]
        end

        subgraph DataAccessLayer ["Data Access & Storage Adapters"]
            PGStore["PostgreSQL Store Adapter\n(Policies, Nodes, Audit, Users)"]
            CHStore["ClickHouse Store Adapter\n(Events, Block ID Lookup, Aggregates)"]
            S3Store["Object Store Adapter\n(MinIO / AWS S3 - Bundles & Samples)"]
        end
    end

    HTTPRouter --> AuthMiddleware --> CoreServices
    GRPCServer --> FleetSvc
    CoreServices --> AuditLogger
    
    PolicySvc --> CompilerSvc
    CompilerSvc --> S3Store
    PolicySvc --> PGStore
    FleetSvc --> PGStore
    EventIngestSvc --> CHStore
    ReplaySvc --> S3Store
```

---

## 4. C4 Level 4: Code & Data Flow / Deployment Diagram

### 4.1. Vòng đời Request và Quyết định WAF (Request Decision Pipeline)

```mermaid
sequenceDiagram
    autonumber
    actor Client as Khách hàng
    participant Nginx as NGINX Worker (C)
    participant Mod as ngx_http_strata
    participant FFI as Rust FFI Interface
    participant Engine as libstrata Engine
    participant Agent as strata-agent (Go)
    participant Upstream as Backend API

    Client->>Nginx: HTTP Request (Headers, URI)
    Nginx->>Mod: PREACCESS Hook
    Mod->>FFI: strata_tx_inspect_preaccess(uri, headers)
    FFI->>Engine: Parse URL, Normalize Headers, Check Rules
    
    alt Phát hiện tấn công ở Header/URI (Score >= Threshold hoặc Block_Alone)
        Engine-->>FFI: Verdict: BLOCK (Block ID, Rule ID, Finding)
        FFI-->>Mod: Action = BLOCK (Mã Block ID: blk_xyz123)
        Mod->>Agent: Gửi Security Event (Datagram Socket)
        Mod-->>Nginx: Trả về trang lỗi 403 Forbidden (Block ID template)
        Nginx-->>Client: 403 Forbidden (Hiển thị Block ID)
    else Hợp lệ ở Header/URI
        Engine-->>FFI: Verdict: PASS (hoặc SHADOW finding)
        FFI-->>Mod: Action = PASS
        Nginx->>Mod: ACCESS Hook (Đọc Request Body)
        Mod->>FFI: strata_tx_inspect_body(body_chunks)
        FFI->>Engine: Parse Body (JSON/Multipart), Run Hyperscan & Detectors
        
        critical Kiểm tra CPU Budget (Hợp tác)
            Engine->>Engine: Giới hạn ngân sách thực thi <= 10ms
        end

        alt Body có vi phạm tấn công (SQLi / XSS / CMDi)
            Engine-->>FFI: Verdict: BLOCK
            FFI-->>Mod: Action = BLOCK
            Mod->>Agent: Gửi Security Event chi tiết (Datagram Socket)
            Mod-->>Nginx: 403 Forbidden
            Nginx-->>Client: 403 Forbidden
        else Body an toàn
            Engine-->>FFI: Verdict: PASS
            FFI-->>Mod: Action = PASS
            Mod-->>Nginx: Cho phép request đi tiếp
            Nginx->>Upstream: Forward Request đến Backend
            Upstream-->>Nginx: HTTP Response (Status, Headers, Body)
            Nginx->>Mod: HEADER_FILTER & BODY_FILTER Hooks
            Mod->>FFI: strata_tx_inspect_response(body)
            FFI->>Engine: DLP Scanner (Kiểm tra rò rỉ CCCD, PAN, JWT, DB Error)
            Engine-->>FFI: Verdict: PASS (hoặc Redact / Log alert)
            FFI-->>Mod: Clean Response
            Mod-->>Nginx: Gửi Response
            Nginx-->>Client: Phản hồi an toàn cho Khách hàng
        end
    end
```

### 4.2. Luồng Phát hành Chính sách & Ký số Bundle (Policy Distribution)

```mermaid
sequenceDiagram
    autonumber
    actor SecOps as Security Engineer
    participant UI as Strata Web UI
    participant CP as Control Plane API
    participant Compiler as Bundle Compiler
    participant S3 as Object Storage (MinIO)
    participant Agent as strata-agent
    participant Nginx as NGINX Module

    SecOps->>UI: Chỉnh sửa Policy (Rules, Route matching, Thresholds)
    UI->>CP: POST /v1/policies (Tạo bản nháp Draft)
    SecOps->>UI: Yêu cầu Replay kiểm thử trên traffic mẫu
    UI->>CP: POST /v1/policies/{id}:replay
    CP-->>UI: Kết quả Replay (0 FP, phát hiện đúng attack)
    SecOps->>UI: Submit duyệt (Bật luồng 4 mắt)
    actor Approver as Lead SecOps
    Approver->>UI: Duyệt chính sách (Approve)
    UI->>CP: POST /v1/policies/{id}:approve
    
    CP->>Compiler: Biên dịch IR thành Bundle Binary (.sbn)
    Compiler->>Compiler: Tạo Hyperscan Block DB + Metadata Index
    Compiler->>Compiler: Ký số Bundle bằng Ed25519 Private Key
    Compiler->>S3: Tải Bundle đã ký lên Object Store
    
    CP->>Agent: gRPC Notification: BundleAvailable(Version, Checksum, URL, CanaryGroup)
    Agent->>S3: Tải file Bundle (.sbn) qua HTTPS
    Agent->>Agent: Xác minh chữ ký số Ed25519 bằng Public Key cục bộ
    Agent->>Agent: Ghi file bundle nguyên tử vào /var/lib/strata/bundles/
    Agent->>Agent: Cập nhật file điều khiển strata.ctl (Atomic rename)
    
    Nginx->>Nginx: Đọc inode của strata.ctl (Zero reload overhead)
    Nginx->>Nginx: Atomic Pointer Swap mmap sang Bundle mới
    Note over Nginx: Toàn bộ Worker áp dụng chính sách mới trong < 1 giây!
```

---

## 5. Ma trận Giao thức & Kết nối Mạng (Network & Protocol Matrix)

| Chiều giao tiếp | Nguồn | Đích | Giao thức | Cổng | Cơ chế Bảo mật & Xác thực | Mục đích |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **Inbound Web** | Client / Internet | NGINX Proxy | HTTPS / HTTP2 / HTTP3 | 443, 80 | TLS 1.3, HSTS | Nhận lưu lượng người dùng |
| **IPC Nội bộ Node** | NGINX Module | strata-agent | Unix Domain Socket | `/run/strata/events.sock` | File system permissions (`0660`, group `strata`) | Đẩy sự kiện WAF non-blocking |
| **IPC Nội bộ Node** | strata-agent | NGINX Module | Shared Memory / FS | `/dev/shm`, `/var/lib/strata` | Kernel shm permissions, read-only mmap | Đọc metrics, nhận bundle, kiểm tra cờ tắt rule |
| **Management Mesh** | strata-agent | Control Plane | gRPC over HTTP/2 | 8443 | **Mutual TLS (mTLS)** với chứng chỉ Node CA riêng | Heartbeat, kéo bundle, stream sự kiện, nhận lệnh khẩn |
| **Admin Access** | Web UI / Browser | Control Plane | HTTPS | 443 / 8080 | TLS 1.3 + OIDC Bearer Token / Local JWT HttpOnly | Giao diện quản trị và điều hành SOC |
| **Event Pipeline** | Control Plane | ClickHouse | Native TCP / HTTP | 9000 / 8123 | TLS, User/Password, Dedicated DB `strata` | Lưu trữ sự kiện vi phạm và thống kê Block ID |
| **Relational Data** | Control Plane | PostgreSQL | PostgreSQL Wire | 5432 | TLS, Certificate/Password, Dedicated DB | Quản lý cấu hình, người dùng, audit log |
| **Artifact Store** | CP & Agent | MinIO / AWS S3 | HTTPS | 9000 / 443 | S3 IAM Signature v4 / TLS | Lưu trữ bundle nhị phân, parquet replay |

---

## 6. Mô hình Triển khai Hạ tầng (Deployment Topology)

```mermaid
flowchart TD
    subgraph InternetDMZ ["DMZ / Edge Network"]
        subgraph EdgeHost1 ["Edge Proxy Node 01"]
            NGINX1["NGINX Gateway + libstrata"]
            Agent1["strata-agent"]
        end
        subgraph EdgeHost2 ["Edge Proxy Node 02"]
            NGINX2["NGINX Gateway + libstrata"]
            Agent2["strata-agent"]
        end
        LB["Network Load Balancer (NLB)\n(Anycast / L4 DSR)"]
    end

    subgraph InternalMgmtVPC ["Management VPC (Phân vùng Cô lập)"]
        subgraph CPCluster ["Control Plane High-Availability"]
            CPInstance1["strata-control-plane #1"]
            CPInstance2["strata-control-plane #2"]
            InternalLB["Internal ALB (mTLS termination / passthrough)"]
        end

        subgraph DBCluster ["Cụm Dữ liệu Đa tầng"]
            PGPrimary["PostgreSQL Primary"]
            PGStandby["PostgreSQL Standby"]
            CHCluster["ClickHouse 2-Shard Cluster (Zookeeper/Keeper)"]
            MinIOCluster["MinIO Distributed 4-Node"]
        end
    end

    LB --> NGINX1
    LB --> NGINX2
    Agent1 ==|"mTLS Outbound"|==> InternalLB
    Agent2 ==|"mTLS Outbound"|==> InternalLB
    InternalLB --> CPInstance1
    InternalLB --> CPInstance2

    CPInstance1 --> PGPrimary
    CPInstance2 --> PGPrimary
    PGPrimary -.->|"Streaming Replication"| PGStandby
    CPInstance1 --> CHCluster
    CPInstance2 --> CHCluster
    CPInstance1 --> MinIOCluster
    CPInstance2 --> MinIOCluster
```

Tài liệu này xác lập cấu trúc chuẩn mực về Topology C4 cho hệ thống Strata WAF, làm cơ sở cho công tác kiểm toán mã nguồn, vận hành và mở rộng quy mô.
