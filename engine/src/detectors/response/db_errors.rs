//! Database error messages in a response body: the application leaks its
//! SQL errors, typical of an injection being probed. Rules 600101-600107,
//! one per database family, recorded only. Case-insensitive literals,
//! tried only where the byte matches the first byte of a signature: no
//! allocation and no global state (the module can be unloaded; a static
//! automaton showed up as leaked under Valgrind after dlclose).
#![forbid(unsafe_code)]

use super::digit;
use crate::guard::{Ctx, Hit, Matcher};

pub const MYSQL: u32 = 600_101;
pub const POSTGRESQL: u32 = 600_102;
pub const MSSQL: u32 = 600_103;
pub const ORACLE: u32 = 600_104;
pub const SQLITE: u32 = 600_105;
pub const DB2: u32 = 600_106;
pub const GENERIC: u32 = 600_107;

/// "ORA-" must be followed by 5 digits.
const ORA: &str = "ORA-";
const ORA_DIGITS: usize = 5;

const SIGNATURES: &[(&str, u32)] = &[
    ("You have an error in your SQL syntax", MYSQL),
    ("corresponds to your MySQL server version", MYSQL),
    ("Warning: mysql_", MYSQL),
    ("mysqli_sql_exception", MYSQL),
    ("MySqlException", MYSQL),
    ("com.mysql.jdbc", MYSQL),
    ("PostgreSQL query failed", POSTGRESQL),
    ("pg_query(): Query failed", POSTGRESQL),
    ("PG::SyntaxError", POSTGRESQL),
    ("org.postgresql.util.PSQLException", POSTGRESQL),
    ("ERROR:  syntax error at or near", POSTGRESQL),
    ("Npgsql.PostgresException", POSTGRESQL),
    ("Unclosed quotation mark after the character string", MSSQL),
    ("Microsoft OLE DB Provider for SQL Server", MSSQL),
    ("[Microsoft][ODBC SQL Server Driver]", MSSQL),
    ("System.Data.SqlClient.SqlException", MSSQL),
    ("Microsoft.Data.SqlClient.SqlException", MSSQL),
    ("com.microsoft.sqlserver.jdbc", MSSQL),
    (ORA, ORACLE),
    ("quoted string not properly terminated", ORACLE),
    ("oracle.jdbc.driver", ORACLE),
    ("SQLite3::SQLException", SQLITE),
    ("sqlite3.OperationalError", SQLITE),
    ("System.Data.SQLite.SQLiteException", SQLITE),
    ("SQLITE_ERROR", SQLITE),
    ("DB2 SQL error", DB2),
    ("com.ibm.db2.jcc", DB2),
    ("SQLSTATE[", GENERIC),
    ("java.sql.SQLException", GENERIC),
    ("java.sql.SQLSyntaxErrorException", GENERIC),
    ("Microsoft JET Database Engine", GENERIC),
    ("Syntax error in string in query expression", GENERIC),
];

/// The first signature (list order) matching at `hay[i..]`.
fn signature_at(hay: &[u8], i: usize) -> Option<usize> {
    let c = hay[i].to_ascii_lowercase();
    SIGNATURES.iter().position(|(sig, _)| {
        let sig = sig.as_bytes();
        sig[0].to_ascii_lowercase() == c
            && hay.len() - i >= sig.len()
            && hay[i..i + sig.len()].eq_ignore_ascii_case(sig)
    })
}

pub struct DbErrors;

impl Matcher for DbErrors {
    fn max_len(&self) -> usize {
        let longest = SIGNATURES.iter().map(|(s, _)| s.len()).max().unwrap_or(0);
        longest.max(ORA.len() + ORA_DIGITS)
    }

    fn masks(&self) -> bool {
        false
    }

    fn find(&mut self, hay: &[u8], ctx: Ctx, out: &mut Vec<Hit>) {
        let mut i = 0;
        while i < hay.len() {
            let Some(k) = signature_at(hay, i) else {
                i += 1;
                continue;
            };
            let (sig, rule) = SIGNATURES[k];
            let start = i;
            let mut end = i + sig.len();
            if sig == ORA {
                // upper case, a word of its own, 5 digits (all in the
                // window: the tail held back covers them)
                let before = match start {
                    0 => ctx.before,
                    j => Some(hay[j - 1]),
                };
                let digits = &hay[end..hay.len().min(end + ORA_DIGITS)];
                if &hay[start..end] != ORA.as_bytes()
                    || before.is_some_and(|c| c.is_ascii_alphanumeric())
                    || digits.len() < ORA_DIGITS
                    || !digits.iter().all(|&c| digit(c))
                {
                    i += 1;
                    continue;
                }
                end += ORA_DIGITS;
            }
            out.push(Hit { start, end, rule });
            i = end;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::guard::{Guard, tests::run};

    fn found(chunks: &[&[u8]]) -> Vec<u32> {
        let mut g = Guard::new(vec![Box::new(DbErrors)], true);
        let out = run(&mut g, chunks);
        assert_eq!(out, chunks.concat(), "never rewritten");
        g.found().to_vec()
    }

    #[test]
    fn families() {
        let cases: &[(&[u8], u32)] = &[
            (b"<b>you have an ERROR in your sql syntax</b>", MYSQL),
            (b"PG::SyntaxError: ERROR", POSTGRESQL),
            (
                b"Unclosed quotation mark after the character string ''.",
                MSSQL,
            ),
            (b"ORA-00933: SQL command not properly ended", ORACLE),
            (b"SQLite3::SQLException: near", SQLITE),
            (b"DB2 SQL error: SQLCODE=-104", DB2),
            (b"SQLSTATE[42000]: Syntax error", GENERIC),
        ];
        for (body, rule) in cases {
            assert_eq!(found(&[body]), [*rule], "{}", body.escape_ascii());
        }
    }

    #[test]
    fn split_between_chunks() {
        let body = b"Warning: PostgreSQL query failed: ERROR";
        for s in 0..=body.len() {
            assert_eq!(found(&[&body[..s], &body[s..]]), [POSTGRESQL], "{s}");
        }
    }

    #[test]
    fn ora_needs_five_digits() {
        assert!(found(&[b"ORA-12 and ora-00933 and FLORA-00933"]).is_empty());
        assert_eq!(found(&[b"ORA-0", b"0933"]), [ORACLE]);
    }

    #[test]
    fn ordinary_text() {
        assert!(found(&[b"An error occurred. Please check your input."]).is_empty());
    }
}
