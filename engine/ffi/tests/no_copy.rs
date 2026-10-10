//! W04-R-01: strata_engine_map builds the engine on the caller's mapping and
//! copies none of it. A counting global allocator measures the bytes
//! allocated while mapping a 16 MB bundle through the C entry point.

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use libstrata::bundle::{Mode, Spec, build, public_key};
use libstrata::rules::{BlockPage, encode};
use strata::abi::{STRATA_OK, strata_err_t, strata_str_t};
use strata::ffi::{strata_engine_map, strata_engine_policy, strata_engine_release};

struct Counting;

static COUNTING: AtomicBool = AtomicBool::new(false);
static ALLOCATED: AtomicUsize = AtomicUsize::new(0);

// SAFETY: forwards to the system allocator; only adds a counter.
unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        if COUNTING.load(Ordering::Relaxed) {
            ALLOCATED.fetch_add(layout.size(), Ordering::Relaxed);
        }
        unsafe { System.alloc(layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        unsafe { System.dealloc(ptr, layout) }
    }
}

#[global_allocator]
static GLOBAL: Counting = Counting;

#[test]
fn mapping_a_16_mb_bundle_copies_nothing() {
    const SEED: [u8; 32] = [4; 32];
    const PAD: usize = 16 << 20;

    let page = BlockPage {
        html: vec![b'x'; 1000],
        support_contact: b"support@example.test".to_vec(),
    };
    let mut sections = encode(&[], Some(&page));
    sections.push((0x7fff, vec![0x5a; PAD])); // large section the engine skips
    let refs: Vec<(u32, &[u8])> = sections.iter().map(|(k, b)| (*k, &b[..])).collect();
    let spec = Spec {
        version: 1,
        created_at_ms: 0,
        flags: 0,
        policies: &[("example-api", Mode::Enforce)],
        sections: &refs,
    };
    let bundle = build(&spec, &SEED).unwrap();
    let key = public_key(&SEED);
    assert!(bundle.len() > PAD);

    let mut err = strata_err_t {
        code: -1,
        msg: [0; 256],
    };
    ALLOCATED.store(0, Ordering::Relaxed);
    COUNTING.store(true, Ordering::Relaxed);
    // SAFETY: bundle and key outlive the engine, released below.
    let e = unsafe { strata_engine_map(bundle.as_ptr(), bundle.len(), key.as_ptr(), &mut err) };
    COUNTING.store(false, Ordering::Relaxed);
    let allocated = ALLOCATED.load(Ordering::Relaxed);

    assert!(!e.is_null() && err.code == STRATA_OK);
    assert!(
        allocated < 64 * 1024,
        "{allocated} bytes allocated to map {} bytes",
        bundle.len()
    );
    println!(
        "mapped {} bytes with {allocated} bytes allocated",
        bundle.len()
    );

    // and it does read the mapping in place
    let mut info = Default::default();
    let name = strata_str_t {
        ptr: b"example-api".as_ptr(),
        len: 11,
    };
    // SAFETY: e is live; name valid for the call.
    assert_eq!(
        unsafe { strata_engine_policy(e, name, &mut info) },
        STRATA_OK
    );
    // SAFETY: last reference.
    unsafe { strata_engine_release(e) };
}
