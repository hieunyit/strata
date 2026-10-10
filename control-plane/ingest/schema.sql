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

    INDEX idx_ts timestamp TYPE minmax GRANULARITY 1,
    INDEX idx_policy policy_id TYPE set(100) GRANULARITY 2,
    INDEX idx_action action TYPE set(10) GRANULARITY 1,
    INDEX idx_rules matched_rules TYPE set(100) GRANULARITY 2
)
ENGINE = MergeTree()
PARTITION BY toYYYYMMDD(timestamp)
PRIMARY KEY block_id
ORDER BY (block_id, timestamp)
TTL timestamp + INTERVAL 90 DAY
SETTINGS index_granularity = 8192;
