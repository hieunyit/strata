//! XML request bodies, for rule targets (CRS `XML:/*` and `XML://@*`):
//! the text of the document (its text and CDATA nodes, joined) and the
//! value of every attribute, with the predefined and numeric character
//! references decoded. Iterative and bounded; DTDs are skipped, never
//! expanded (no entity expansion, no external fetch). A document that
//! does not parse yields what was read before the damage.
#![forbid(unsafe_code)]

/// At most this many attribute values are kept.
pub const MAX_ATTRS: usize = 1024;

#[derive(Debug, Default, PartialEq, Eq)]
pub struct Xml {
    /// text and CDATA content, in document order
    pub text: Vec<u8>,
    /// attribute values, decoded
    pub attrs: Vec<Vec<u8>>,
    /// attributes past MAX_ATTRS were left out (rule 100021)
    pub attrs_left_out: bool,
}

/// Whether a Content-Type is XML: text/xml, application/xml, */*+xml.
pub fn is_xml(content_type: &[u8]) -> bool {
    let media = media_type(content_type);
    media.eq_ignore_ascii_case(b"text/xml")
        || media.eq_ignore_ascii_case(b"application/xml")
        || (media.len() > 4 && media[media.len() - 4..].eq_ignore_ascii_case(b"+xml"))
}

/// The media type of a Content-Type, without parameters.
pub fn media_type(ct: &[u8]) -> &[u8] {
    let end = ct.iter().position(|&c| c == b';').unwrap_or(ct.len());
    trim(&ct[..end])
}

fn memchr_8k(
    needle: u8,
    slice: &[u8],
    mut budget: Option<&mut crate::budget::TxBudget>,
) -> Result<Option<usize>, crate::budget::BudgetExceeded> {
    let mut curr = 0;
    while curr < slice.len() {
        if curr > 0
            && let Some(bgt) = budget.as_mut()
        {
            bgt.check()?;
        }
        let end = (curr + 8192).min(slice.len());
        if let Some(pos) = memchr::memchr(needle, &slice[curr..end]) {
            return Ok(Some(curr + pos));
        }
        curr = end;
    }
    Ok(None)
}

fn memmem_8k(
    haystack: &[u8],
    needle: &[u8],
    mut budget: Option<&mut crate::budget::TxBudget>,
) -> Result<Option<usize>, crate::budget::BudgetExceeded> {
    if needle.is_empty() {
        return Ok(Some(0));
    }
    let finder = memchr::memmem::Finder::new(needle);
    let mut curr = 0;
    while curr < haystack.len() {
        if curr > 0
            && let Some(bgt) = budget.as_mut()
        {
            bgt.check()?;
        }
        let end = (curr + 8192 + needle.len() - 1).min(haystack.len());
        if end < curr + needle.len() {
            break;
        }
        if let Some(pos) = finder.find(&haystack[curr..end]) {
            return Ok(Some(curr + pos));
        }
        curr += 8192;
    }
    Ok(None)
}

pub fn parse_with_budget(
    b: &[u8],
    budget: Option<&mut crate::budget::TxBudget>,
) -> Result<Xml, crate::budget::BudgetExceeded> {
    Ok(parse_checked_with_budget(b, budget)?.0)
}

/// As `parse_with_budget`, and whether the whole document was read (#97):
/// false when a tag, comment, CDATA section or declaration does not end.
pub fn parse_checked_with_budget(
    b: &[u8],
    mut budget: Option<&mut crate::budget::TxBudget>,
) -> Result<(Xml, bool), crate::budget::BudgetExceeded> {
    let mut x = Xml::default();
    let mut i = 0;
    while i < b.len() {
        if b[i] != b'<' {
            let end = memchr_8k(b'<', &b[i..], budget.as_deref_mut())?.map_or(b.len(), |e| i + e);
            decode_into(&b[i..end], &mut x.text, budget.as_deref_mut())?;
            i = end;
            continue;
        }
        let rest = &b[i..];
        let next = if rest.starts_with(b"<?") {
            memmem_8k(&rest[2..], b"?>", budget.as_deref_mut())?.map(|e| i + 2 + e + 2)
        } else if rest.starts_with(b"<!--") {
            memmem_8k(&rest[4..], b"-->", budget.as_deref_mut())?.map(|e| i + 4 + e + 3)
        } else if rest.starts_with(b"<![CDATA[") {
            memmem_8k(&rest[9..], b"]]>", budget.as_deref_mut())?.map(|e| {
                x.text.extend_from_slice(&rest[9..9 + e]);
                i + 9 + e + 3
            })
        } else if rest.starts_with(b"<!") {
            doctype_end(rest, budget.as_deref_mut())?.map(|e| i + e)
        } else if rest.starts_with(b"</") {
            memchr_8k(b'>', rest, budget.as_deref_mut())?.map(|e| i + e + 1)
        } else {
            start_tag(
                rest,
                &mut x.attrs,
                &mut x.attrs_left_out,
                budget.as_deref_mut(),
            )?
            .map(|e| i + e)
        };
        match next {
            Some(n) => i = n,
            None => return Ok((x, false)),
        }
    }
    Ok((x, true))
}

pub fn parse(b: &[u8]) -> Xml {
    parse_with_budget(b, None).unwrap()
}

/// End of `<!DOCTYPE ...>`, with an internal subset `[...]` skipped.
fn doctype_end(
    rest: &[u8],
    mut budget: Option<&mut crate::budget::TxBudget>,
) -> Result<Option<usize>, crate::budget::BudgetExceeded> {
    let Some(gt) = memchr_8k(b'>', rest, budget.as_deref_mut())? else {
        return Ok(None);
    };
    match memchr_8k(b'[', &rest[..gt], budget.as_deref_mut())? {
        Some(open) => Ok(memmem_8k(&rest[open..], b"]>", budget)?.map(|e| open + e + 2)),
        None => Ok(Some(gt + 1)),
    }
}

/// A start tag at `rest[0] == '<'`: its attribute values go to `attrs`;
/// returns the length of the tag.
fn start_tag(
    rest: &[u8],
    attrs: &mut Vec<Vec<u8>>,
    left_out: &mut bool,
    mut budget: Option<&mut crate::budget::TxBudget>,
) -> Result<Option<usize>, crate::budget::BudgetExceeded> {
    let mut j = 1;
    // element name
    while j < rest.len() && !is_space(rest[j]) && rest[j] != b'>' && rest[j] != b'/' {
        j += 1;
    }
    if j == 1 {
        return Ok(None);
    }
    loop {
        while j < rest.len() && is_space(rest[j]) {
            j += 1;
        }
        match rest.get(j) {
            Some(&b'>') => return Ok(Some(j + 1)),
            Some(&b'/') if rest.get(j + 1) == Some(&b'>') => return Ok(Some(j + 2)),
            None => return Ok(None),
            _ => {}
        }
        // name = "value"
        let name_start = j;
        while j < rest.len() && rest[j] != b'=' && !is_space(rest[j]) && rest[j] != b'>' {
            j += 1;
        }
        if j == name_start {
            return Ok(None);
        }
        while j < rest.len() && is_space(rest[j]) {
            j += 1;
        }
        if rest.get(j) != Some(&b'=') {
            return Ok(None);
        }
        j += 1;
        while j < rest.len() && is_space(rest[j]) {
            j += 1;
        }
        let Some(&q) = rest.get(j) else {
            return Ok(None);
        };
        if q != b'"' && q != b'\'' {
            return Ok(None);
        }
        let Some(c) = memchr_8k(q, &rest[j + 1..], budget.as_deref_mut())? else {
            return Ok(None);
        };
        let close = c + j + 1;
        if attrs.len() < MAX_ATTRS {
            let mut v = Vec::with_capacity(close - j - 1);
            decode_into(&rest[j + 1..close], &mut v, budget.as_deref_mut())?;
            attrs.push(v);
        } else {
            *left_out = true;
        }
        j = close + 1;
    }
}

/// Appends `s` with `&lt; &gt; &amp; &quot; &apos; &#N; &#xH;` decoded;
/// anything else is kept as written.
fn decode_into(
    s: &[u8],
    out: &mut Vec<u8>,
    mut budget: Option<&mut crate::budget::TxBudget>,
) -> Result<(), crate::budget::BudgetExceeded> {
    let mut i = 0;
    while i < s.len() {
        let Some(amp) = memchr_8k(b'&', &s[i..], budget.as_deref_mut())? else {
            out.extend_from_slice(&s[i..]);
            return Ok(());
        };
        out.extend_from_slice(&s[i..i + amp]);
        i += amp;
        let semi = s[i..].iter().take(12).position(|&c| c == b';');
        let decoded = semi.and_then(|e| reference(&s[i + 1..i + e]).map(|c| (c, e)));
        match decoded {
            Some((c, e)) => {
                let mut buf = [0; 4];
                out.extend_from_slice(c.encode_utf8(&mut buf).as_bytes());
                i += e + 1;
            }
            None => {
                out.push(b'&');
                i += 1;
            }
        }
    }
    Ok(())
}

fn reference(name: &[u8]) -> Option<char> {
    match name {
        b"lt" => Some('<'),
        b"gt" => Some('>'),
        b"amp" => Some('&'),
        b"quot" => Some('"'),
        b"apos" => Some('\''),
        [b'#', b'x' | b'X', hex @ ..] if !hex.is_empty() => {
            char::from_u32(u32::from_str_radix(std::str::from_utf8(hex).ok()?, 16).ok()?)
        }
        [b'#', dec @ ..] if !dec.is_empty() => {
            char::from_u32(std::str::from_utf8(dec).ok()?.parse().ok()?)
        }
        _ => None,
    }
}

fn is_space(c: u8) -> bool {
    matches!(c, b' ' | b'\t' | b'\r' | b'\n')
}

fn trim(v: &[u8]) -> &[u8] {
    let start = v.iter().position(|&c| !is_space(c)).unwrap_or(v.len());
    let end = v
        .iter()
        .rposition(|&c| !is_space(c))
        .map_or(start, |e| e + 1);
    &v[start..end]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn content_types() {
        for ct in [
            &b"text/xml"[..],
            b"application/xml; charset=utf-8",
            b"application/soap+xml",
            b" Application/XML ",
        ] {
            assert!(is_xml(ct), "{}", String::from_utf8_lossy(ct));
        }
        for ct in [&b"application/json"[..], b"text/html", b"xml", b"+xml"] {
            assert!(!is_xml(ct), "{}", String::from_utf8_lossy(ct));
        }
    }

    #[test]
    fn text_and_attributes() {
        let x = parse(
            br#"<?xml version="1.0"?><!-- c <a x="no"> --><!DOCTYPE r [<!ENTITY e SYSTEM "file:///etc/passwd">]>
<root a="1 &lt;b&gt;" b='&#x41;&#66;&amp;'><t>ftp%3A%2F%2F</t><![CDATA[<x>]]><e/>&e;</root>"#,
        );
        assert_eq!(x.attrs, [b"1 <b>".to_vec(), b"AB&".to_vec()]);
        assert_eq!(
            x.text, b"\nftp%3A%2F%2F<x>&e;",
            "comments and DTD skipped, entity not expanded"
        );
    }

    #[test]
    fn damaged_documents_end_the_parse() {
        assert_eq!(parse(b"<a x=1>t</a>").attrs, Vec::<Vec<u8>>::new());
        let x = parse(b"<a k=\"v\">text<b unterminated=\"");
        assert_eq!((x.attrs.len(), &x.text[..]), (1, &b"text"[..]));
        assert_eq!(parse(b"<!-- never closed").text, b"");
        assert_eq!(parse(b"").text, b"");
        assert_eq!(
            parse(b"&#xFFFFFFFF; &#; &unknown; &").text,
            b"&#xFFFFFFFF; &#; &unknown; &"
        );
    }

    #[test]
    fn at_most_max_attrs() {
        let doc = [b"<a ".as_slice(), &b"k=\"v\" ".repeat(MAX_ATTRS + 3), b"/>"].concat();
        let x = parse(&doc);
        assert_eq!(x.attrs.len(), MAX_ATTRS);
        assert!(
            x.attrs_left_out,
            "the ones left out are reported (rule 100021)"
        );
        assert!(!parse(b"<a k=\"v\"/>").attrs_left_out);
    }

    /// #97: whether the whole document was read.
    #[test]
    fn complete_only_when_every_markup_ends() {
        let whole = |b: &[u8]| parse_checked_with_budget(b, None).unwrap().1;
        assert!(whole(
            b"<?xml version=\"1.0\"?><a x=\"1\">t<![CDATA[c]]><!-- k --></a>"
        ));
        assert!(whole(b"<!DOCTYPE a [<!ENTITY x \"y\">]><a/>"));
        for bad in [
            &b"<a>t</a><!-- open"[..],
            b"<a x=\"1\"",
            b"<![CDATA[x",
            b"<?xml version",
        ] {
            assert!(!whole(bad), "{}", String::from_utf8_lossy(bad));
        }
    }
}
