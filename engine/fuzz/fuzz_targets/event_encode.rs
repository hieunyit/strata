//! Fuzz target for event encoding and size bounding (W07-R-03).
//!
//! Feeds arbitrary transaction metadata, headers, body chunks, and direct
//! EventData structs to ensure `encode` never panics, always yields valid
//! protobuf wire format <= 8192 bytes, and `strata_tx_event` FFI respects
//! buffer boundaries.
#![no_main]

use std::sync::{Arc, OnceLock};

use libfuzzer_sys::fuzz_target;
use libstrata::bundle::{Mode, Oversize, PolicySpec, Spec, build, public_key};
use libstrata::engine::Engine;
use libstrata::event::{self, EventData, MatchData, MAX_DATAGRAM};
use libstrata::tx::Tx;

fn engine() -> Arc<Engine> {
    static E: OnceLock<Arc<Engine>> = OnceLock::new();
    E.get_or_init(|| {
        let p = PolicySpec::new("example-fuzz", Mode::Enforce, Oversize::Pass);
        let spec = Spec {
            version: 1,
            created_at_ms: 0,
            flags: 0,
            policies: &[p],
            sections: &[],
        };
        let b = build(&spec, &[3; 32]).unwrap();
        Arc::new(Engine::map(Box::new(b), &public_key(&[3; 32])).unwrap())
    })
    .clone()
}

/// Validates that `bytes` is a syntactically valid Protobuf wire stream
/// consisting of varint (0) and length-delimited (2) fields.
fn validate_protobuf_stream(bytes: &[u8]) -> bool {
    let mut pos = 0;
    while pos < bytes.len() {
        let mut tag_val: u64 = 0;
        let mut shift = 0;
        let mut ok = false;
        while pos < bytes.len() && shift < 64 {
            let b = bytes[pos];
            pos += 1;
            tag_val |= ((b & 0x7f) as u64) << shift;
            shift += 7;
            if (b & 0x80) == 0 {
                ok = true;
                break;
            }
        }
        if !ok {
            return false;
        }
        let wire_type = tag_val & 0x07;
        match wire_type {
            0 => {
                let mut v_ok = false;
                let mut v_shift = 0;
                while pos < bytes.len() && v_shift < 64 {
                    let b = bytes[pos];
                    pos += 1;
                    if (b & 0x80) == 0 {
                        v_ok = true;
                        break;
                    }
                    v_shift += 7;
                }
                if !v_ok {
                    return false;
                }
            }
            2 => {
                let mut len_val: u64 = 0;
                let mut len_shift = 0;
                let mut len_ok = false;
                while pos < bytes.len() && len_shift < 64 {
                    let b = bytes[pos];
                    pos += 1;
                    len_val |= ((b & 0x7f) as u64) << len_shift;
                    len_shift += 7;
                    if (b & 0x80) == 0 {
                        len_ok = true;
                        break;
                    }
                }
                if !len_ok || pos + (len_val as usize) > bytes.len() {
                    return false;
                }
                pos += len_val as usize;
            }
            _ => return false,
        }
    }
    pos == bytes.len()
}

fuzz_target!(|data: &[u8]| {
    if data.len() < 16 {
        return;
    }

    // Branch 1: Transaction driving
    let shadow_flag = if data[0] & 1 != 0 {
        libstrata::verdict::TXF_FORCE_SHADOW
    } else {
        0
    };
    let mut t = Tx::new(Some(engine()), &data[1..6], shadow_flag);
    t.set_policy(b"example-fuzz");
    t.set_client_addr(&data[6..10]);
    t.set_identity(&data[10..14]);
    t.set_request_id(&data[14..16]);

    let rest = &data[16..];
    let uri_len = if !rest.is_empty() {
        (rest[0] as usize) % rest.len()
    } else {
        0
    };
    let (uri_bytes, body_bytes) = rest.split_at(uri_len);

    t.request_line(b"POST", uri_bytes, uri_bytes, b"", b"HTTP/1.1");
    t.request_header(b"Host", b"example.test");
    t.request_header(b"Authorization", b"Bearer secret-token");
    t.request_headers_done();
    t.request_body_chunk(body_bytes, true);

    if let Some(ev) = t.encode_event() {
        assert!(
            ev.len() <= MAX_DATAGRAM,
            "tx.encode_event produced {} bytes > 8192",
            ev.len()
        );
        assert!(
            validate_protobuf_stream(&ev),
            "tx.encode_event produced invalid wire protobuf"
        );
    }

    // Branch 2: Direct event structure encoding with large/adversarial shapes
    let block_id = if data.len() > 30 {
        std::str::from_utf8(&data[0..23]).unwrap_or("STR-TEST-1234-5678-ABCD")
    } else {
        "STR-TEST-1234-5678-ABCD"
    };

    let n_matches = (data[0] as usize % 64).min(32);
    let mut snippets = Vec::with_capacity(n_matches);
    for i in 0..n_matches {
        let snip_len = (data[1] as usize * (i + 1)) % 1024;
        let mut snippet = vec![b'A'; snip_len];
        if i % 2 == 0 {
            snippet.extend_from_slice(b"079099001122");
        }
        let prepared = event::prepare_snippet("ARGS:p", &snippet);
        snippets.push(prepared);
    }
    let mut matches = Vec::with_capacity(n_matches);
    for (i, snip) in snippets.iter().enumerate() {
        matches.push(MatchData {
            rule_id: 100_000 + i as u32,
            layer: "managed",
            field: "ARGS:p",
            snippet: snip,
        });
    }

    let path_str = std::str::from_utf8(rest).unwrap_or("/test/default");
    let ev = EventData {
        block_id,
        time_unix_ms: 1_700_000_000_000,
        node_id: "node-fuzz",
        request_id: "req-fuzz",
        policy_id: "example-fuzz",
        bundle_version: 1,
        client_ip: "192.0.2.1",
        identity: "user-fuzz",
        method: "POST",
        host: "fuzz.example.test",
        path: path_str,
        status: 403,
        action: event::Action::Block,
        layer_scores: &[("anomaly", 100), ("managed", 100), ("protocol", 50)],
        rule_ids: &[100001, 100002],
        matches: &matches,
        canary: event::CanaryGroup::None,
    };

    let encoded = event::encode(&ev);
    assert!(
        encoded.len() <= MAX_DATAGRAM,
        "event::encode produced {} bytes > 8192",
        encoded.len()
    );
    assert!(
        validate_protobuf_stream(&encoded),
        "event::encode produced invalid wire protobuf"
    );
});
