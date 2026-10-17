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

    -- W16-G2-01: GeoIP and network metadata
    country_iso      LowCardinality(String) CODEC(ZSTD(1)),
    city             LowCardinality(String) CODEC(ZSTD(1)),
    lat              Float32 CODEC(DoubleDelta, ZSTD(1)),
    lon              Float32 CODEC(DoubleDelta, ZSTD(1)),
    asn              UInt32 CODEC(T64, ZSTD(1)),
    as_org           String CODEC(ZSTD(1)),

    INDEX idx_ts timestamp TYPE minmax GRANULARITY 1,
    INDEX idx_policy policy_id TYPE set(100) GRANULARITY 2,
    INDEX idx_action action TYPE set(10) GRANULARITY 1,
    INDEX idx_rules matched_rules TYPE set(100) GRANULARITY 2,
    INDEX idx_country country_iso TYPE set(250) GRANULARITY 2,
    INDEX idx_asn asn TYPE minmax GRANULARITY 2
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

-- W20-G2-01: Hourly Materialized Views for Overview Performance Optimization
-- Guarantees 24h query in < 1s and 30d query in < 3s SLA.

CREATE TABLE IF NOT EXISTS events_stats_hourly (
    hour        DateTime CODEC(DoubleDelta, ZSTD(1)),
    policy_id   LowCardinality(String),
    action      LowCardinality(String),
    is_error    UInt8 CODEC(T64, ZSTD(1)),
    count       UInt64,
    blocked     UInt64,
    shadowed    UInt64,
    other       UInt64,
    error_count UInt64
) ENGINE = SummingMergeTree()
PARTITION BY toYYYYMM(hour)
PRIMARY KEY (hour, policy_id, action)
ORDER BY (hour, policy_id, action)
TTL hour + INTERVAL 13 MONTH;

CREATE MATERIALIZED VIEW IF NOT EXISTS events_stats_hourly_mv TO events_stats_hourly AS
SELECT
    toStartOfHour(timestamp) AS hour,
    policy_id,
    action,
    if(action = 'error', 1, 0) AS is_error,
    count() AS count,
    countIf(action = 'block') AS blocked,
    countIf(action = 'shadow') AS shadowed,
    countIf(action NOT IN ('block', 'shadow')) AS other,
    countIf(action = 'error') AS error_count
FROM events
GROUP BY hour, policy_id, action, is_error;

CREATE TABLE IF NOT EXISTS events_rules_hourly (
    hour        DateTime CODEC(DoubleDelta, ZSTD(1)),
    policy_id   LowCardinality(String),
    rule_id     UInt32 CODEC(T64, ZSTD(1)),
    events      UInt64,
    blocked     UInt64,
    shadowed    UInt64
) ENGINE = SummingMergeTree()
PARTITION BY toYYYYMM(hour)
PRIMARY KEY (hour, policy_id, rule_id)
ORDER BY (hour, policy_id, rule_id)
TTL hour + INTERVAL 13 MONTH;

CREATE MATERIALIZED VIEW IF NOT EXISTS events_rules_hourly_mv TO events_rules_hourly AS
SELECT
    toStartOfHour(timestamp) AS hour,
    policy_id,
    rule_id,
    count() AS events,
    countIf(action = 'block') AS blocked,
    countIf(action = 'shadow') AS shadowed
FROM events
ARRAY JOIN arrayDistinct(matched_rules) AS rule_id
GROUP BY hour, policy_id, rule_id;

CREATE TABLE IF NOT EXISTS events_routes_hourly (
    hour        DateTime CODEC(DoubleDelta, ZSTD(1)),
    policy_id   LowCardinality(String),
    http_host   LowCardinality(String),
    path_prefix String CODEC(ZSTD(2)),
    events      UInt64,
    blocked     UInt64,
    shadowed    UInt64,
    error_count UInt64
) ENGINE = SummingMergeTree()
PARTITION BY toYYYYMM(hour)
PRIMARY KEY (hour, policy_id, http_host, path_prefix)
ORDER BY (hour, policy_id, http_host, path_prefix)
TTL hour + INTERVAL 13 MONTH;

CREATE MATERIALIZED VIEW IF NOT EXISTS events_routes_hourly_mv TO events_routes_hourly AS
SELECT
    toStartOfHour(timestamp) AS hour,
    policy_id,
    http_host,
    arrayStringConcat(arraySlice(splitByChar('/', path(concat('http://h', http_path))), 1, 3), '/') AS path_prefix,
    count() AS events,
    countIf(action = 'block') AS blocked,
    countIf(action = 'shadow') AS shadowed,
    countIf(action = 'error') AS error_count
FROM events
GROUP BY hour, policy_id, http_host, path_prefix;

