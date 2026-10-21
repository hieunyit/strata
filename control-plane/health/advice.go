package health

// NextStep uses fixed text; dependency/agent error strings are never echoed.
func NextStep(id string) string {
	switch id {
	case "postgres":
		return "Check PostgreSQL connectivity and schema version."
	case "lease":
		return "Run one control plane; check lease renewal and process health."
	case "clickhouse", "ingest_lag":
		return "Restore ClickHouse connectivity and inspect ingest delivery."
	case "artifact_disk", "postgres_disk", "clickhouse_disk":
		return "Check the corresponding volume and retention; free space before deploying."
	case "heartbeat":
		return "Check agent service and its mTLS connection."
	case "certificate":
		return "Check automatic certificate renewal before expiry."
	case "bundle_drift":
		return "Inspect rollout errors and wait for ACTIVE acknowledgment."
	case "spool_bytes", "spool_pending", "spool_dropped", "dropped_events":
		return "Restore event delivery and inspect spool capacity; drops are cumulative."
	case "requests", "not_inspected", "body_skipped", "breaker", "fail_open":
		return "Check worker metrics, request limits and inspection failures."
	case "failed_operations":
		return "Inspect failed operations and replay evidence before retrying."
	default:
		return "Check source availability and observation time; missing telemetry is unknown."
	}
}
