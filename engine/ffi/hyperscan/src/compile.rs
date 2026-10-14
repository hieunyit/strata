//! Pattern compilation (feature `compile`, full libhs.a).

use std::ffi::{CStr, CString, c_char, c_int, c_uint, c_void};

use super::{AlignedBuf, HsDatabase, hs_error_t};

#[repr(C)]
struct HsCompileError {
    message: *const c_char,
    expression: c_int,
}

#[repr(C)]
struct HsPlatformInfo {
    tune: c_uint,
    cpu_features: u64,
    reserved1: u64,
    reserved2: u64,
}

pub const CASELESS: u32 = 1;
pub const DOTALL: u32 = 2;
pub const MULTILINE: u32 = 4;
pub const SINGLEMATCH: u32 = 8;
pub const ALLOWEMPTY: u32 = 16;
pub const HS_MODE_BLOCK: u32 = 1;
pub const HS_MODE_STREAM: u32 = 2;
const HS_TUNE_FAMILY_GENERIC: c_uint = 0;

unsafe extern "C" {
    fn hs_compile_multi(
        expressions: *const *const c_char,
        flags: *const c_uint,
        ids: *const c_uint,
        elements: c_uint,
        mode: c_uint,
        platform: *const HsPlatformInfo,
        db: *mut *mut HsDatabase,
        error: *mut *mut HsCompileError,
    ) -> hs_error_t;
    fn hs_free_compile_error(error: *mut HsCompileError) -> hs_error_t;
    fn hs_free_database(db: *mut HsDatabase) -> hs_error_t;
    fn hs_serialize_database(
        db: *const HsDatabase,
        bytes: *mut *mut c_char,
        length: *mut usize,
    ) -> hs_error_t;
    fn hs_serialized_database_size(
        bytes: *const c_char,
        length: usize,
        size: *mut usize,
    ) -> hs_error_t;
    fn hs_deserialize_database_at(
        bytes: *const c_char,
        length: usize,
        db: *mut HsDatabase,
    ) -> hs_error_t;
}

pub struct Pattern {
    pub expression: Vec<u8>,
    pub flags: u32,
    pub id: u32,
}

/// Compiles patterns in streaming mode (`HS_MODE_STREAM`) for a generic x86-64 target and returns
/// the in-memory image, as produced in a 4 KB-aligned buffer, to be stored
/// in a bundle section. Err: (index of the pattern, message).
pub fn compile(patterns: &[Pattern]) -> Result<Vec<u8>, (usize, String)> {
    compile_mode(patterns, HS_MODE_STREAM)
}

/// Compiles patterns with a specific mode (`HS_MODE_STREAM` or `HS_MODE_BLOCK`).
pub fn compile_mode(patterns: &[Pattern], mode: u32) -> Result<Vec<u8>, (usize, String)> {
    let exprs: Vec<CString> = patterns
        .iter()
        .map(|p| CString::new(p.expression.clone()))
        .collect::<Result<_, _>>()
        .map_err(|e| (e.nul_position(), "pattern contains a NUL byte".to_string()))?;
    let ptrs: Vec<*const c_char> = exprs.iter().map(|e| e.as_ptr()).collect();
    let flags: Vec<c_uint> = patterns.iter().map(|p| p.flags).collect();
    let ids: Vec<c_uint> = patterns.iter().map(|p| p.id).collect();
    let n = c_uint::try_from(patterns.len()).map_err(|_| (0, "too many patterns".to_string()))?;
    let platform = HsPlatformInfo {
        tune: HS_TUNE_FAMILY_GENERIC,
        cpu_features: 0,
        reserved1: 0,
        reserved2: 0,
    };

    let mut db: *mut HsDatabase = std::ptr::null_mut();
    let mut err: *mut HsCompileError = std::ptr::null_mut();
    // SAFETY: arrays of n valid elements; outputs are written by Hyperscan.
    let rc = unsafe {
        hs_compile_multi(
            ptrs.as_ptr(),
            flags.as_ptr(),
            ids.as_ptr(),
            n,
            mode as c_uint,
            &platform,
            &mut db,
            &mut err,
        )
    };
    if rc != 0 {
        // SAFETY: on failure err is set (or NULL); message is NUL-terminated.
        let (index, msg) = unsafe {
            if err.is_null() {
                (0, format!("hs_compile_multi failed ({rc})"))
            } else {
                let m = CStr::from_ptr((*err).message)
                    .to_string_lossy()
                    .into_owned();
                let i = (*err).expression.max(0) as usize;
                hs_free_compile_error(err);
                (i, m)
            }
        };
        return Err((index, msg));
    }

    let mut ser: *mut c_char = std::ptr::null_mut();
    let mut ser_len = 0usize;
    let mut size = 0usize;
    // SAFETY: db is valid; outputs written by Hyperscan.
    let image = unsafe {
        let ok = hs_serialize_database(db, &mut ser, &mut ser_len) == 0
            && hs_serialized_database_size(ser, ser_len, &mut size) == 0;
        hs_free_database(db);
        if !ok {
            return Err((0, "hs_serialize_database failed".into()));
        }
        // the image is built in a page-aligned buffer, as at mapping time
        let buf = AlignedBuf::from_bytes(&vec![0u8; size]);
        let rc = hs_deserialize_database_at(ser, ser_len, buf.as_ref().as_ptr().cast_mut().cast());
        libc_free_ser(ser.cast());
        if rc != 0 {
            return Err((0, format!("hs_deserialize_database_at failed ({rc})")));
        }
        buf.as_ref().to_vec()
    };
    Ok(image)
}

unsafe extern "C" {
    #[link_name = "free"]
    fn libc_free_ser(p: *mut c_void);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::MappedDb;

    #[test]
    fn compile_map_and_scan() {
        let pats = vec![
            Pattern {
                expression: b"union\\s+select".to_vec(),
                flags: CASELESS | SINGLEMATCH,
                id: 7,
            },
            Pattern {
                expression: b"\\x2fetc\\x2fpasswd".to_vec(),
                flags: SINGLEMATCH,
                id: 9,
            },
        ];
        // 1. Block mode with db.scan
        let image_block = compile_mode(&pats, HS_MODE_BLOCK).unwrap();
        let buf_block = AlignedBuf::from_bytes(&image_block);
        let db_block = MappedDb::validate(buf_block.as_ref()).unwrap();
        let mut hits = vec![];
        db_block
            .scan(b"x UNION  SELECT 1 from /etc/passwd", &mut |id| {
                hits.push(id);
                true
            })
            .unwrap();
        hits.sort();
        assert_eq!(hits, [7, 9]);
        // early stop in block mode
        let mut n = 0;
        db_block
            .scan(b"union select /etc/passwd", &mut |_| {
                n += 1;
                false
            })
            .unwrap();
        assert_eq!(n, 1);

        // 2. Stream mode with db.scan_stream_chunks
        let image_stream = compile(&pats).unwrap();
        let buf_stream = AlignedBuf::from_bytes(&image_stream);
        let db_stream = MappedDb::validate(buf_stream.as_ref()).unwrap();
        let mut stream_hits = vec![];
        db_stream
            .scan_stream_chunks(
                b"x UNION  SELECT 1 from /etc/passwd",
                8192,
                || true,
                &mut |id| {
                    stream_hits.push(id);
                    true
                },
            )
            .unwrap();
        stream_hits.sort();
        assert_eq!(stream_hits, [7, 9]);
    }

    /// A bundle's stream and block databases (same patterns) are used in
    /// turn on one thread: the scratch grows for both, the open stream is
    /// kept, and both give the same matches, end-anchored ones included.
    #[test]
    fn stream_and_block_databases_share_the_thread_scratch() {
        let mut pats: Vec<Pattern> = (0..400)
            .map(|i| Pattern {
                expression: format!("w{i}x[a-z]{{2,5}}\\d").into_bytes(),
                flags: CASELESS | SINGLEMATCH,
                id: i,
            })
            .collect();
        pats.push(Pattern {
            expression: b"tail$".to_vec(),
            flags: SINGLEMATCH,
            id: 1000,
        });
        let small = vec![Pattern {
            expression: b"abc".to_vec(),
            flags: 0,
            id: 0,
        }];
        let (bs, bb, bt) = (
            AlignedBuf::from_bytes(&compile(&pats).unwrap()),
            AlignedBuf::from_bytes(&compile_mode(&pats, HS_MODE_BLOCK).unwrap()),
            AlignedBuf::from_bytes(&compile_mode(&small, HS_MODE_BLOCK).unwrap()),
        );
        // ids as the engine gives them: one per database
        let stream = MappedDb::assume_valid_with_id(bs.as_ref(), 41);
        let block = MappedDb::assume_valid_with_id(bb.as_ref(), 41 | (1 << 62));
        let tiny = MappedDb::validate(bt.as_ref()).unwrap();
        let via_stream = |data: &[u8]| {
            let mut h = vec![];
            stream
                .scan_stream_chunks(data, 2048, || true, &mut |id| {
                    h.push(id);
                    true
                })
                .unwrap();
            h.sort();
            h
        };
        let via_block = |db: &MappedDb<'_>, data: &[u8]| {
            let mut h = vec![];
            db.scan(data, &mut |id| {
                h.push(id);
                true
            })
            .unwrap();
            h.sort();
            h
        };
        // the small block database first: the scratch is too small for the
        // others until they grow it
        assert_eq!(via_block(&tiny, b"xxabcxx"), [0]);
        let inputs: [&[u8]; 4] = [
            b"W7Xab1 and w399xzzzzz9 tail",
            b"tail",
            b"nothing",
            b"w12xqq3 tai",
        ];
        for _ in 0..3 {
            for data in inputs {
                let s = via_stream(data);
                assert_eq!(
                    via_block(&block, data),
                    s,
                    "{:?}",
                    String::from_utf8_lossy(data)
                );
                assert_eq!(via_block(&tiny, data), Vec::<u32>::new());
            }
        }
        assert_eq!(via_stream(b"x w5xabc0 tail"), [5, 1000]);
    }

    #[test]
    fn bad_pattern_reports_its_index() {
        let pats = vec![
            Pattern {
                expression: b"ok".to_vec(),
                flags: 0,
                id: 0,
            },
            Pattern {
                expression: b"(a)\\1".to_vec(),
                flags: 0,
                id: 1,
            }, // backreference
        ];
        let (i, msg) = compile(&pats).unwrap_err();
        assert_eq!(i, 1, "{msg}");
    }

    #[test]
    fn damaged_or_misaligned_images_are_refused() {
        let image = compile(&[Pattern {
            expression: b"abc".to_vec(),
            flags: 0,
            id: 0,
        }])
        .unwrap();
        let buf = AlignedBuf::from_bytes(&image);
        assert!(MappedDb::validate(buf.as_ref()).is_ok());
        // misaligned view
        let mut shifted = vec![0u8; image.len() + 1];
        shifted[1..].copy_from_slice(&image);
        let sb = AlignedBuf::from_bytes(&shifted);
        assert_eq!(
            MappedDb::validate(&sb.as_ref()[1..]).unwrap_err(),
            crate::Error::Misaligned
        );
        // bytecode damage is caught by the CRC check
        let mut bad = image.clone();
        let at = bad.len() - 100;
        bad[at] ^= 0xff;
        let bb = AlignedBuf::from_bytes(&bad);
        assert!(MappedDb::validate(bb.as_ref()).is_err());
    }
}
