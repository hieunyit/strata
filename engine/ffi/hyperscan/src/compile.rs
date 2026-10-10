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
const HS_MODE_BLOCK: c_uint = 1;
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

/// Compiles patterns (block mode) for a generic x86-64 target and returns
/// the in-memory image, as produced in a 4 KB-aligned buffer, to be stored
/// in a bundle section. Err: (index of the pattern, message).
pub fn compile(patterns: &[Pattern]) -> Result<Vec<u8>, (usize, String)> {
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
            HS_MODE_BLOCK,
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
        let image = compile(&pats).unwrap();
        let buf = AlignedBuf::from_bytes(&image);
        let db = MappedDb::validate(buf.as_ref()).unwrap();
        let mut hits = vec![];
        db.scan(b"x UNION  SELECT 1 from /etc/passwd", &mut |id| {
            hits.push(id);
            true
        })
        .unwrap();
        hits.sort();
        assert_eq!(hits, [7, 9]);
        // early stop
        let mut n = 0;
        db.scan(b"union select /etc/passwd", &mut |_| {
            n += 1;
            false
        })
        .unwrap();
        assert_eq!(n, 1);
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
