//! libinjection XSS port and its HTML5 tokenizer, every starting context.
#![no_main]

use libfuzzer_sys::fuzz_target;
use libstrata::detectors::injection::html5::{Flags, Html5};
use libstrata::detectors::injection::xss;

fuzz_target!(|data: &[u8]| {
    let _ = xss::detect(data);
    let mut h = Html5::new(data, Flags::DataState);
    while h.next_token() {
        assert!(h.token_start + h.token_len <= data.len());
    }
});
