//! Name rules that depend on the local file system, and conflict names.

use oxisoft_drive_proto::{MAX_NAME_LEN, Name};

/// Whether Windows allows `name` (sync protocol §8): no `< > : " \ | ? *`, no control
/// characters, no trailing dot or space, and not a reserved device name (`CON`, `PRN`, `AUX`,
/// `NUL`, `COM1`–`COM9`, `LPT1`–`LPT9`, with or without an extension, in any case).
#[must_use]
pub fn windows_allows(name: &Name) -> bool {
    let text = name.as_str();
    let forbidden = text
        .chars()
        .any(|c| matches!(c, '<' | '>' | ':' | '"' | '\\' | '|' | '?' | '*') || c.is_control());
    if forbidden || text.ends_with(['.', ' ']) {
        return false;
    }
    let stem = text.split('.').next().unwrap_or(text).to_ascii_uppercase();
    let reserved = matches!(stem.as_str(), "CON" | "PRN" | "AUX" | "NUL")
        || ((stem.starts_with("COM") || stem.starts_with("LPT"))
            && stem.len() == 4
            && stem.as_bytes()[3].is_ascii_digit()
            && stem.as_bytes()[3] != b'0');
    !reserved
}

/// The conflict name for `original`: `stem (tag).ext`, or `stem (tag n).ext` for the n-th
/// attempt (n ≥ 2). The stem is shortened on a character boundary if the result would exceed
/// the name length limit.
#[must_use]
pub fn conflict_name(original: &Name, tag: &str, attempt: u32) -> Name {
    let text = original.as_str();
    // A leading dot starts a hidden name, not an extension.
    let (stem, ext) = match text.rfind('.') {
        Some(dot) if dot > 0 => text.split_at(dot),
        _ => (text, ""),
    };
    let label = if attempt > 1 {
        format!(" ({tag} {attempt})")
    } else {
        format!(" ({tag})")
    };
    let budget = MAX_NAME_LEN.saturating_sub(label.len() + ext.len());
    let mut cut = stem.len().min(budget);
    while !stem.is_char_boundary(cut) {
        cut -= 1;
    }
    let candidate = format!("{}{label}{ext}", &stem[..cut]);
    // The tag comes from our own code and the stem from a valid name, so this only fails if
    // the tag itself contains `/` or NUL; fall back to a plain numbered name then.
    Name::new(&candidate).unwrap_or_else(|_| {
        Name::new(&format!("conflict {attempt}")).unwrap_or_else(|_| original.clone())
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn name(text: &str) -> Name {
        Name::new(text).unwrap()
    }

    #[test]
    fn windows_rules() {
        for ok in [
            "report.txt",
            "CONSOLE",
            "com0",
            "COM10",
            "lpt",
            "a.b.c",
            "日本",
        ] {
            assert!(windows_allows(&name(ok)), "{ok}");
        }
        for bad in [
            "a:b",
            "a?",
            "q\"",
            "x|y",
            "star*",
            "back\\slash",
            "<a>",
            "dot.",
            "space ",
            "CON",
            "con.txt",
            "Nul",
            "COM1",
            "lpt9.log",
            "tab\tname",
        ] {
            assert!(!windows_allows(&name(bad)), "{bad}");
        }
    }

    #[test]
    fn conflict_names() {
        let tag = "conflict 2026-09-28 14.30 laptop";
        assert_eq!(
            conflict_name(&name("report.docx"), tag, 1).as_str(),
            "report (conflict 2026-09-28 14.30 laptop).docx"
        );
        assert_eq!(
            conflict_name(&name("archive.tar.gz"), tag, 2).as_str(),
            "archive.tar (conflict 2026-09-28 14.30 laptop 2).gz"
        );
        assert_eq!(
            conflict_name(&name(".bashrc"), tag, 1).as_str(),
            ".bashrc (conflict 2026-09-28 14.30 laptop)"
        );
        assert_eq!(
            conflict_name(&name("Makefile"), "c", 3).as_str(),
            "Makefile (c 3)"
        );
        let long = "é".repeat(125);
        let shortened = conflict_name(&name(&format!("{long}.txt")), tag, 1);
        assert!(shortened.as_str().len() <= MAX_NAME_LEN);
        assert!(
            shortened
                .as_str()
                .ends_with(" (conflict 2026-09-28 14.30 laptop).txt")
        );
        // An odd byte budget lands inside a two-byte character and backs off.
        let odd = conflict_name(&name(&format!("{long}.txt")), "odd", 1);
        assert!(odd.as_str().len() <= MAX_NAME_LEN);
        assert!(odd.as_str().ends_with("é (odd).txt"), "{odd:?}");
        assert_eq!(
            conflict_name(&name("a.txt"), "bad/tag", 2).as_str(),
            "conflict 2"
        );
    }
}
