-- ClickHouse schema for Strata WAF events v1
-- Optimized for ultra-fast Block ID lookup (primary key) and time-range searches (partition by day + skip index)

CREATE TABLE IF NOT EXISTS events (
    block_id         String CODEC(ZSTD(1)),
    timestamp        DateTime64(3, 'UTC') CODEC(DoubleDelta, ZSTD(1)),

    node_id          LowCardinality(String),
    connector_type   LowCardinality(String),
    policy_id        LowCardinality(String),
    policy_version   UInt64 CODEC(T64, ZSTD(1)),

    client_ip        String CODEC(ZSTD(1)),
    identity         String CODEC(ZSTD(1)),
    request_id       String CODEC(ZSTD(1)),
    http_method      LowCardinality(String),
    http_host        String CODEC(ZSTD(1)),
    http_path        String CODEC(ZSTD(3)),
    status_code      UInt16 CODEC(T64, ZSTD(1)),
    action           LowCardinality(String),

    score_protocol   Int32 CODEC(T64, ZSTD(1)),
    score_sqli       Int32 CODEC(T64, ZSTD(1)),
    score_xss        Int32 CODEC(T64, ZSTD(1)),
    score_anomaly    Int32 CODEC(T64, ZSTD(1)),

    matched_rules    Array(UInt32),

    violations Nested (
        rule_id      UInt32,
        layer        LowCardinality(String),
        field        String,
        snippet      String
    ),

    received_at      DateTime64(3, 'UTC') DEFAULT now64(3) CODEC(DoubleDelta, ZSTD(1)),

    -- RV-G2-01: the request's context, masked by the engine. RV-N-01: how
    -- much of it was inspected. Tables made before these columns get them
    -- from the control plane at start (ClickHouseStore.EnsureColumns).
    user_agent       String CODEC(ZSTD(1)),
    referer          String CODEC(ZSTD(1)),
    headers Nested (
        name         LowCardinality(String),
        value        String
    ),
    inspection       LowCardinality(String),

    -- Server-resolved GeoIP metadata. Unknown coordinates stay NULL.
    country_iso      LowCardinality(String),
    region           String CODEC(ZSTD(1)),
    city             String CODEC(ZSTD(1)),
    lat              Nullable(Float64),
    lon              Nullable(Float64),
    accuracy_km      Nullable(UInt16),
    asn              UInt32,
    as_org           String CODEC(ZSTD(1)),
    geoip_version    String CODEC(ZSTD(1)),

    -- RV-N-02: JA4 of the client's TLS connection, empty without one.
    ja4              String CODEC(ZSTD(1)),

    -- Optional top-eight sampled rule timings, not all rule executions.
    rule_costs Nested (
        rule_id      UInt32,
        samples      UInt64,
        total_ns     UInt64,
        max_ns       UInt64
    ),

    INDEX idx_ts timestamp TYPE minmax GRANULARITY 1,
    INDEX idx_policy policy_id TYPE set(100) GRANULARITY 2,
    INDEX idx_action action TYPE set(10) GRANULARITY 1,
    INDEX idx_rules matched_rules TYPE set(100) GRANULARITY 2
)
ENGINE = ReplacingMergeTree(received_at)
PARTITION BY toYYYYMMDD(timestamp)
PRIMARY KEY block_id
ORDER BY (block_id, timestamp)
TTL timestamp + INTERVAL 90 DAY
SETTINGS index_granularity = 8192;

CREATE TABLE IF NOT EXISTS node_seq (
    node_id    LowCardinality(String),
    last_seq   UInt64,
    updated_at DateTime64(3, 'UTC') DEFAULT now64(3)
)
ENGINE = ReplacingMergeTree(updated_at)
PRIMARY KEY node_id
ORDER BY node_id;


-- RV-N-01: requests per node, policy and heartbeat interval, from the
-- workers' counters (engine/src/counters.rs): the denominator of the share
-- of requests not fully inspected. The control plane also creates it at
-- start (ClickHouseStore.EnsurePolicyRequests).
CREATE TABLE IF NOT EXISTS policy_requests (
    timestamp        DateTime64(3, 'UTC') CODEC(DoubleDelta, ZSTD(1)),
    node_id          LowCardinality(String),
    policy_id        LowCardinality(String),
    requests         UInt64 CODEC(T64, ZSTD(1)),
    partial          UInt64 CODEC(T64, ZSTD(1)),
    body_skipped     UInt64 CODEC(T64, ZSTD(1)),
    error            UInt64 CODEC(T64, ZSTD(1)),
    degraded         UInt64 CODEC(T64, ZSTD(1))
)
ENGINE = MergeTree
PARTITION BY toYYYYMMDD(timestamp)
ORDER BY (policy_id, timestamp)
TTL timestamp + INTERVAL 90 DAY;
