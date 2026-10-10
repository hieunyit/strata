//! libstrata-ffi — the C ABI of libstrata (`strata.h`), built as
//! `libstrata.a`. This crate is the only place where `unsafe` is allowed;
//! the engine itself is the safe `libstrata` crate (`engine/`).

pub mod abi;
pub mod ffi;

// The engine's codes are the ABI's codes: keep them identical.
const _: () = {
    use abi::*;
    use libstrata::verdict as v;
    assert!(v::OK == STRATA_OK);
    assert!(v::E_INVALID == STRATA_E_INVALID);
    assert!(v::E_STATE == STRATA_E_STATE);
    assert!(v::E_INTERNAL == STRATA_E_INTERNAL);
    assert!(v::E_BUDGET == STRATA_E_BUDGET);
    assert!(v::E_BUNDLE == STRATA_E_BUNDLE);
    assert!(v::E_NOT_FOUND == STRATA_E_NOT_FOUND);
    assert!(v::E_INCOMPLETE == STRATA_E_INCOMPLETE);
    assert!(libstrata::bundle::Mode::Shadow as u32 == STRATA_POLICY_SHADOW);
    assert!(libstrata::bundle::Mode::Enforce as u32 == STRATA_POLICY_ENFORCE);
    assert!(v::ACTION_ALLOW == STRATA_ACTION_ALLOW);
    assert!(v::ACTION_LOG == STRATA_ACTION_LOG);
    assert!(v::ACTION_CHALLENGE == STRATA_ACTION_CHALLENGE);
    assert!(v::ACTION_BLOCK == STRATA_ACTION_BLOCK);
    assert!(v::TXF_FORCE_SHADOW == STRATA_TXF_FORCE_SHADOW);
    assert!(v::MAX_RULES == STRATA_MAX_RULES);
    assert!(v::PUBKEY_LEN == STRATA_PUBKEY_LEN);
    assert!(libstrata::block_id::ID_LEN < STRATA_BLOCK_ID_SIZE);
};
