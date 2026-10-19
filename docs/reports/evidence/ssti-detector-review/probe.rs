#[path = "source-ssti.rs"]
mod original;
#[path = "../../engine/src/detectors/injection/ssti.rs"]
mod repaired;
use std::hint::black_box;
use std::time::Instant;
fn main() {
    let expect_source_fixed = std::env::args().any(|a| a == "--expect-source-fixed");
    for (opener, attack) in [(b"{{".as_slice(), b"{{7*7}}".as_slice()), (b"${", b"${7*7}"), (b"<%", b"<%=7*7%>")] {
        let mut input = opener.repeat(128);
        input.extend_from_slice(attack);
        if expect_source_fixed {
            assert!(original::detect(&input), "source misses nested arithmetic probe");
        } else {
            assert!(!original::detect(&input));
            assert!(repaired::detect(&input));
        }
    }
    println!("PASS: three nested arithmetic regressions reproduce source miss and repaired detection");
    let pieces: &[&[u8]] = &[b"{{", b"${", b"#{", b"*{", b"<%", b"}}", b"}", b"%>", b"7*7", b"name", b"__class__", b"\xff", b"\0", b" ", b"()"];
    let mut state = 17u64;
    let mut added = 0;
    for case in 0..100_000 {
        let mut input = Vec::new();
        for _ in 0..case % 32 {
            state = state.wrapping_mul(6364136223846793005).wrapping_add(1);
            input.extend_from_slice(pieces[(state as usize) % pieces.len()]);
        }
        let old = original::detect(&input);
        let new = repaired::detect(&input);
        assert!(!old || new, "lost source detection at case {case}: {input:?}");
        added += usize::from(!old && new);
    }
    println!("PASS: 100000 deterministic malformed/mixed/arbitrary-byte cases; no lost source detections, {added} additional nested-expression detections");
    for bytes in [16384, 32768, 65536] {
        let input = b"{{".repeat(bytes / 2);
        let mut sample = Vec::new();
        for detector in [original::detect as fn(&[u8]) -> bool, repaired::detect] {
            let start = Instant::now();
            for _ in 0..3 { assert!(!black_box(detector(black_box(&input)))); }
            sample.push(start.elapsed().as_nanos() / 3);
        }
        println!("unclosed_bytes={bytes} original_ns={} repaired_ns={}", sample[0], sample[1]);
    }
}
