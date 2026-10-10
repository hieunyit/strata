//! libinjection SQLi port: any input, every quoting context, the token
//! API used by the original test driver.
#![no_main]

use libfuzzer_sys::fuzz_target;
use libstrata::detectors::injection::sqli::{self, FLAG_QUOTE_NONE, FLAG_SQL_ANSI, State};

fuzz_target!(|data: &[u8]| {
    let _ = sqli::detect(data);
    let mut st = State::new(data, FLAG_QUOTE_NONE | FLAG_SQL_ANSI);
    while st.tokenize() {}
    let mut st = State::new(data, FLAG_QUOTE_NONE | FLAG_SQL_ANSI);
    let n = st.fold();
    // 5 tokens, or up to 7 in the "{ ``" case (as in the C code)
    assert!(n <= 7);
});
