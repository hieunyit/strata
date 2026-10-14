//! strata-hs — thin, safe bindings to Hyperscan (5.x) for Strata.
//!
//! Lives under `engine/ffi/` because it needs `unsafe`. Exposes:
//! - [`MappedDb`]: a database image read in place from a bundle mapping
//!   (validated once: alignment, version/platform, bytecode CRC), scanned
//!   with a per-thread scratch;
//! - with the `compile` feature, [`compile`]: patterns -> in-memory image
//!   for a generic x86-64 target, 4 KB-aligned, ready to be stored in a
//!   bundle section (docs/poc/hyperscan-mmap.md).

use std::cell::RefCell;
use std::ffi::{CStr, c_char, c_int, c_uint, c_ulonglong, c_void};
use std::panic::{AssertUnwindSafe, catch_unwind};

#[allow(non_camel_case_types)]
type hs_error_t = c_int;
#[repr(C)]
struct HsDatabase {
    _p: [u8; 0],
}
#[repr(C)]
struct HsScratch {
    _p: [u8; 0],
}
#[repr(C)]
struct HsStream {
    _p: [u8; 0],
}
type MatchFn = extern "C" fn(c_uint, c_ulonglong, c_ulonglong, c_uint, *mut c_void) -> c_int;

const HS_SUCCESS: hs_error_t = 0;
const HS_SCAN_TERMINATED: hs_error_t = -3;

unsafe extern "C" {
    fn hs_version() -> *const c_char;
    fn hs_database_info(db: *const HsDatabase, info: *mut *mut c_char) -> hs_error_t;
    fn hs_alloc_scratch(db: *const HsDatabase, scratch: *mut *mut HsScratch) -> hs_error_t;
    fn hs_free_scratch(scratch: *mut HsScratch) -> hs_error_t;
    fn hs_scan(
        db: *const HsDatabase,
        data: *const c_char,
        length: c_uint,
        flags: c_uint,
        scratch: *mut HsScratch,
        on_event: MatchFn,
        context: *mut c_void,
    ) -> hs_error_t;
    fn hs_open_stream(
        db: *const HsDatabase,
        flags: c_uint,
        stream: *mut *mut HsStream,
    ) -> hs_error_t;
    fn hs_scan_stream(
        id: *mut HsStream,
        data: *const c_char,
        length: c_uint,
        flags: c_uint,
        scratch: *mut HsScratch,
        on_event: MatchFn,
        context: *mut c_void,
    ) -> hs_error_t;
    fn hs_reset_stream(
        id: *mut HsStream,
        flags: c_uint,
        scratch: *mut HsScratch,
        on_event: Option<MatchFn>,
        context: *mut c_void,
    ) -> hs_error_t;
    fn hs_close_stream(
        id: *mut HsStream,
        scratch: *mut HsScratch,
        on_event: Option<MatchFn>,
        context: *mut c_void,
    ) -> hs_error_t;
}

/// Alignment Hyperscan expects for a database image at any address it is
/// mapped to (the image is produced in a page-aligned buffer).
pub const IMAGE_ALIGN: usize = 64;

/// Hyperscan library version, e.g. "5.4.2 2024-04-19".
pub fn version() -> &'static str {
    // SAFETY: hs_version returns a static NUL-terminated string.
    unsafe { CStr::from_ptr(hs_version()) }
        .to_str()
        .unwrap_or("unknown")
}

#[derive(Debug, PartialEq, Eq)]
pub enum Error {
    Misaligned,
    Invalid(i32),
    Scan(i32),
}

impl Error {
    pub fn message(&self) -> &'static str {
        match self {
            Error::Misaligned => "hyperscan database misaligned",
            Error::Invalid(-5) => "hyperscan database built for another Hyperscan version",
            Error::Invalid(-6) => "hyperscan database built for another platform",
            Error::Invalid(_) => "invalid hyperscan database",
            Error::Scan(_) => "hyperscan scan failed",
        }
    }
}

use std::sync::atomic::{AtomicU64, Ordering};

static NEXT_DB_ID: AtomicU64 = AtomicU64::new(1);

/// A database image inside a bundle mapping (or any buffer that outlives it).
#[derive(Clone, Copy, Debug)]
pub struct MappedDb<'a> {
    bytes: &'a [u8],
    id: u64,
}

struct Scratch {
    ptr: *mut HsScratch,
    /// engine or database ID the scratch and stream were configured for
    /// (stream mode)
    engine_id: u64,
    stream: *mut HsStream,
    /// database ID the scratch was last grown for in block mode. A scratch
    /// grown for a database stays large enough for the ones before it, so
    /// a stream database and a block database of one bundle share it.
    block_id: u64,
}

impl Drop for Scratch {
    fn drop(&mut self) {
        if !self.stream.is_null() {
            // SAFETY: allocated by hs_open_stream, closed once on thread exit.
            unsafe { hs_close_stream(self.stream, self.ptr, None, std::ptr::null_mut()) };
        }
        if !self.ptr.is_null() {
            // SAFETY: allocated by hs_alloc_scratch, freed once.
            unsafe { hs_free_scratch(self.ptr) };
        }
    }
}

thread_local! {
    static SCRATCH: RefCell<Scratch> = const {
        RefCell::new(Scratch {
            ptr: std::ptr::null_mut(),
            engine_id: 0,
            stream: std::ptr::null_mut(),
            block_id: 0,
        })
    };
}

impl<'a> MappedDb<'a> {
    /// Validates an image: alignment, header (magic, version, platform) and
    /// the bytecode CRC, which Hyperscan only checks in hs_alloc_scratch —
    /// hs_scan trusts the bytecode (docs/poc/hyperscan-mmap.md).
    pub fn validate(bytes: &'a [u8]) -> Result<MappedDb<'a>, Error> {
        if bytes.is_empty() || !(bytes.as_ptr() as usize).is_multiple_of(IMAGE_ALIGN) {
            return Err(Error::Misaligned);
        }
        let db = bytes.as_ptr().cast::<HsDatabase>();
        let mut info: *mut c_char = std::ptr::null_mut();
        // SAFETY: db points to readable bytes; Hyperscan checks the header
        // (and its length field) before touching the bytecode.
        let rc = unsafe { hs_database_info(db, &mut info) };
        if rc != HS_SUCCESS {
            return Err(Error::Invalid(rc));
        }
        // SAFETY: allocated by Hyperscan with the default allocator (malloc).
        unsafe { libc_free(info.cast()) };
        let mut s: *mut HsScratch = std::ptr::null_mut();
        // SAFETY: as above; this call verifies the bytecode CRC.
        let rc = unsafe { hs_alloc_scratch(db, &mut s) };
        if !s.is_null() {
            // SAFETY: allocated just above.
            unsafe { hs_free_scratch(s) };
        }
        if rc != HS_SUCCESS {
            return Err(Error::Invalid(rc));
        }
        Ok(MappedDb {
            bytes,
            id: NEXT_DB_ID.fetch_add(1, Ordering::Relaxed),
        })
    }

    /// For an image that already passed [`validate`] (same bytes, still
    /// mapped): no checks, nothing allocated.
    pub fn assume_valid(bytes: &'a [u8]) -> MappedDb<'a> {
        MappedDb {
            bytes,
            id: NEXT_DB_ID.fetch_add(1, Ordering::Relaxed),
        }
    }

    pub fn assume_valid_with_id(bytes: &'a [u8], id: u64) -> MappedDb<'a> {
        MappedDb { bytes, id }
    }

    pub fn id(&self) -> u64 {
        self.id
    }

    /// Scans `data` (block mode); `on_match(pattern_id)` returns `false` to
    /// stop early. Uses this thread's scratch, grown for this database once.
    pub fn scan(&self, data: &[u8], on_match: &mut dyn FnMut(u32) -> bool) -> Result<(), Error> {
        let db = self.bytes.as_ptr().cast::<HsDatabase>();
        let len = c_uint::try_from(data.len()).map_err(|_| Error::Scan(-1))?;
        SCRATCH.with(|cell| {
            let mut s = cell.borrow_mut();
            // the stream of a stream database, if open, is left as it is:
            // block and stream databases of one bundle are used in turn
            if s.block_id != self.id {
                // SAFETY: db was validated; grows (or creates) the scratch.
                let rc = unsafe { hs_alloc_scratch(db, &mut s.ptr) };
                if rc != HS_SUCCESS {
                    return Err(Error::Invalid(rc));
                }
                s.block_id = self.id;
            }
            let mut ctx = Ctx {
                f: on_match,
                panicked: false,
            };
            // SAFETY: db validated, scratch sized for it, ctx outlives the call.
            let rc = unsafe {
                hs_scan(
                    db,
                    data.as_ptr().cast(),
                    len,
                    0,
                    s.ptr,
                    on_event,
                    (&mut ctx as *mut Ctx<'_>).cast(),
                )
            };
            if ctx.panicked {
                return Err(Error::Scan(-1));
            }
            match rc {
                HS_SUCCESS | HS_SCAN_TERMINATED => Ok(()),
                rc => Err(Error::Scan(rc)),
            }
        })
    }

    /// Warms up the thread-local scratch for this block-mode database, so
    /// the first request does not allocate it.
    pub fn warm_block(&self) -> Result<(), Error> {
        let db = self.bytes.as_ptr().cast::<HsDatabase>();
        SCRATCH.with(|cell| {
            let mut s = cell.borrow_mut();
            if s.block_id != self.id {
                // SAFETY: db was validated; grows (or creates) the scratch.
                let rc = unsafe { hs_alloc_scratch(db, &mut s.ptr) };
                if rc != HS_SUCCESS {
                    return Err(Error::Invalid(rc));
                }
                s.block_id = self.id;
            }
            Ok(())
        })
    }

    /// Warms up thread-local scratch and stream state for this database.
    pub fn warm_thread(&self) -> Result<(), Error> {
        let db = self.bytes.as_ptr().cast::<HsDatabase>();
        SCRATCH.with(|cell| {
            let mut s = cell.borrow_mut();
            if s.engine_id != self.id {
                if !s.stream.is_null() {
                    unsafe { hs_close_stream(s.stream, s.ptr, None, std::ptr::null_mut()) };
                    s.stream = std::ptr::null_mut();
                }
                let rc = unsafe { hs_alloc_scratch(db, &mut s.ptr) };
                if rc != HS_SUCCESS {
                    return Err(Error::Invalid(rc));
                }
                s.engine_id = self.id;
            }
            if s.stream.is_null() {
                let rc = unsafe { hs_open_stream(db, 0, &mut s.stream) };
                if rc != HS_SUCCESS {
                    return Err(Error::Invalid(rc));
                }
            }
            Ok(())
        })
    }

    /// Scans `data` in streaming mode chunk by chunk.
    /// `chunk_size` is typically 8192.
    /// Between chunks, `check_budget()` is called. Returns `Ok(false)` if stopped early (budget or match).
    pub fn scan_stream_chunks(
        &self,
        data: &[u8],
        chunk_size: usize,
        mut check_budget: impl FnMut() -> bool,
        on_match: &mut dyn FnMut(u32) -> bool,
    ) -> Result<bool, Error> {
        let db = self.bytes.as_ptr().cast::<HsDatabase>();
        SCRATCH.with(|cell| {
            let mut s = cell.borrow_mut();
            if s.engine_id != self.id {
                if !s.stream.is_null() {
                    unsafe { hs_close_stream(s.stream, s.ptr, None, std::ptr::null_mut()) };
                    s.stream = std::ptr::null_mut();
                }
                let rc = unsafe { hs_alloc_scratch(db, &mut s.ptr) };
                if rc != HS_SUCCESS {
                    return Err(Error::Invalid(rc));
                }
                s.engine_id = self.id;
            }
            if s.stream.is_null() {
                let rc = unsafe { hs_open_stream(db, 0, &mut s.stream) };
                if rc != HS_SUCCESS {
                    return Err(Error::Invalid(rc));
                }
            }
            let stream = s.stream;
            let scratch = s.ptr;

            let mut ctx = Ctx {
                f: on_match,
                panicked: false,
            };

            if data.len() <= chunk_size {
                let len = c_uint::try_from(data.len()).map_err(|_| Error::Scan(-1))?;
                let ptr = if data.is_empty() {
                    std::ptr::null()
                } else {
                    data.as_ptr().cast()
                };
                let rc = unsafe {
                    hs_scan_stream(
                        stream,
                        ptr,
                        len,
                        0,
                        scratch,
                        on_event,
                        (&mut ctx as *mut Ctx<'_>).cast(),
                    )
                };
                if ctx.panicked {
                    let _ =
                        unsafe { hs_reset_stream(stream, 0, scratch, None, std::ptr::null_mut()) };
                    return Err(Error::Scan(-1));
                }
                if rc == HS_SCAN_TERMINATED {
                    let _ =
                        unsafe { hs_reset_stream(stream, 0, scratch, None, std::ptr::null_mut()) };
                    return Ok(false);
                } else if rc != HS_SUCCESS {
                    let _ =
                        unsafe { hs_reset_stream(stream, 0, scratch, None, std::ptr::null_mut()) };
                    return Err(Error::Scan(rc));
                }
            } else {
                for chunk in data.chunks(chunk_size) {
                    if !check_budget() {
                        let _ = unsafe {
                            hs_reset_stream(stream, 0, scratch, None, std::ptr::null_mut())
                        };
                        return Ok(false);
                    }
                    let len = c_uint::try_from(chunk.len()).map_err(|_| Error::Scan(-1))?;
                    let rc = unsafe {
                        hs_scan_stream(
                            stream,
                            chunk.as_ptr().cast(),
                            len,
                            0,
                            scratch,
                            on_event,
                            (&mut ctx as *mut Ctx<'_>).cast(),
                        )
                    };
                    if ctx.panicked {
                        let _ = unsafe {
                            hs_reset_stream(stream, 0, scratch, None, std::ptr::null_mut())
                        };
                        return Err(Error::Scan(-1));
                    }
                    if rc == HS_SCAN_TERMINATED {
                        let _ = unsafe {
                            hs_reset_stream(stream, 0, scratch, None, std::ptr::null_mut())
                        };
                        return Ok(false);
                    } else if rc != HS_SUCCESS {
                        let _ = unsafe {
                            hs_reset_stream(stream, 0, scratch, None, std::ptr::null_mut())
                        };
                        return Err(Error::Scan(rc));
                    }
                }
            }

            let rc = unsafe {
                hs_reset_stream(
                    stream,
                    0,
                    scratch,
                    Some(on_event),
                    (&mut ctx as *mut Ctx<'_>).cast(),
                )
            };
            if ctx.panicked {
                return Err(Error::Scan(-1));
            }
            if rc == HS_SCAN_TERMINATED {
                Ok(false)
            } else if rc != HS_SUCCESS {
                Err(Error::Scan(rc))
            } else {
                Ok(true)
            }
        })
    }

    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }
}

struct Ctx<'f> {
    f: &'f mut dyn FnMut(u32) -> bool,
    panicked: bool,
}

extern "C" fn on_event(
    id: c_uint,
    _from: c_ulonglong,
    _to: c_ulonglong,
    _flags: c_uint,
    ctx: *mut c_void,
) -> c_int {
    // SAFETY: ctx is the &mut Ctx passed to hs_scan, alive for the call.
    let ctx = unsafe { &mut *ctx.cast::<Ctx<'_>>() };
    // no panic may unwind through Hyperscan's C++ frames
    match catch_unwind(AssertUnwindSafe(|| (ctx.f)(id))) {
        Ok(true) => 0,
        Ok(false) => 1,
        Err(_) => {
            ctx.panicked = true;
            1
        }
    }
}

unsafe extern "C" {
    #[link_name = "free"]
    fn libc_free(p: *mut c_void);
}

/// A buffer whose start is 4 KB-aligned, for images held outside a mapping
/// (tests, the compiler).
pub struct AlignedBuf {
    pages: Vec<Page>,
    len: usize,
}

#[repr(C, align(4096))]
#[derive(Clone, Copy)]
struct Page([u8; 4096]);

impl AlignedBuf {
    pub fn from_bytes(src: &[u8]) -> AlignedBuf {
        let mut pages = vec![Page([0; 4096]); src.len().div_ceil(4096).max(1)];
        for (p, chunk) in pages.iter_mut().zip(src.chunks(4096)) {
            p.0[..chunk.len()].copy_from_slice(chunk);
        }
        AlignedBuf {
            pages,
            len: src.len(),
        }
    }
}

impl AsRef<[u8]> for AlignedBuf {
    fn as_ref(&self) -> &[u8] {
        // SAFETY: pages are contiguous plain bytes, len <= pages * 4096.
        unsafe { std::slice::from_raw_parts(self.pages.as_ptr().cast::<u8>(), self.len) }
    }
}

#[cfg(feature = "compile")]
pub mod compile;
#[cfg(feature = "compile")]
pub use compile::{HS_MODE_BLOCK, Pattern, compile, compile_mode};
