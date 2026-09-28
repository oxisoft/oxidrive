//! Paths relative to a collection root.

use std::fmt;

use oxisoft_drive_proto::{Name, ProtoError};

/// A path inside a collection: zero or more valid [`Name`]s. The empty path is the root.
#[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Default)]
pub struct RelPath(Vec<Name>);

impl RelPath {
    /// The collection root.
    #[must_use]
    pub const fn root() -> Self {
        Self(Vec::new())
    }

    /// Parses `a/b/c`, validating and normalising every component.
    ///
    /// # Errors
    ///
    /// [`ProtoError::InvalidName`] for an invalid component (including empty ones, so `a//b`
    /// and a leading or trailing `/` are rejected).
    pub fn parse(path: &str) -> Result<Self, ProtoError> {
        if path.is_empty() {
            return Ok(Self::root());
        }
        path.split('/')
            .map(Name::new)
            .collect::<Result<_, _>>()
            .map(Self)
    }

    /// This path with `name` appended.
    #[must_use]
    pub fn join(&self, name: Name) -> Self {
        let mut components = self.0.clone();
        components.push(name);
        Self(components)
    }

    /// The containing folder, or `None` for the root.
    #[must_use]
    pub fn parent(&self) -> Option<Self> {
        self.0.split_last().map(|(_, parent)| Self(parent.to_vec()))
    }

    /// The last component, or `None` for the root.
    #[must_use]
    pub fn name(&self) -> Option<&Name> {
        self.0.last()
    }

    /// The components.
    #[must_use]
    pub fn components(&self) -> &[Name] {
        &self.0
    }

    /// Whether this is the root.
    #[must_use]
    pub fn is_root(&self) -> bool {
        self.0.is_empty()
    }

    /// Whether `self` is `ancestor` or lies below it.
    #[must_use]
    pub fn starts_with(&self, ancestor: &Self) -> bool {
        self.0.starts_with(&ancestor.0)
    }

    /// Every proper ancestor, from the outermost (excluding the root) to the parent.
    #[must_use]
    pub fn ancestors(&self) -> Vec<Self> {
        (1..self.0.len())
            .map(|len| Self(self.0[..len].to_vec()))
            .collect()
    }

    /// Case-folded form, for detecting clashes on case-insensitive file systems.
    #[must_use]
    pub fn fold_case(&self) -> String {
        self.0
            .iter()
            .map(Name::fold_case)
            .collect::<Vec<_>>()
            .join("/")
    }

    /// This path with its last component replaced by `name`.
    #[must_use]
    pub fn with_name(&self, name: Name) -> Self {
        self.parent().unwrap_or_default().join(name)
    }
}

impl fmt::Display for RelPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (i, name) in self.0.iter().enumerate() {
            if i > 0 {
                f.write_str("/")?;
            }
            f.write_str(name.as_str())?;
        }
        Ok(())
    }
}

impl fmt::Debug for RelPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "RelPath({self})")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn path(text: &str) -> RelPath {
        RelPath::parse(text).unwrap()
    }

    #[test]
    fn parsing_and_display() {
        assert!(path("").is_root());
        assert_eq!(path("a/b/c").to_string(), "a/b/c");
        assert_eq!(format!("{:?}", path("a/b")), "RelPath(a/b)");
        for bad in ["/a", "a/", "a//b", "a/../b", "a/./b"] {
            assert!(RelPath::parse(bad).is_err(), "{bad}");
        }
        assert_eq!(path("Cafe\u{301}"), path("Caf\u{e9}"));
    }

    #[test]
    fn navigation() {
        let p = path("a/b/c");
        assert_eq!(p.parent(), Some(path("a/b")));
        assert_eq!(path("a").parent(), Some(RelPath::root()));
        assert_eq!(RelPath::root().parent(), None);
        assert_eq!(p.name().map(Name::as_str), Some("c"));
        assert_eq!(RelPath::root().name(), None);
        assert_eq!(p.components().len(), 3);
        assert!(
            p.starts_with(&path("a/b")) && p.starts_with(&p) && p.starts_with(&RelPath::root())
        );
        assert!(!path("a/bc").starts_with(&path("a/b")));
        assert_eq!(p.ancestors(), vec![path("a"), path("a/b")]);
        assert!(path("a").ancestors().is_empty());
        assert_eq!(path("a/b").join(Name::new("c").unwrap()), p);
        assert_eq!(p.with_name(Name::new("d").unwrap()), path("a/b/d"));
        assert_eq!(path("x").with_name(Name::new("y").unwrap()), path("y"));
        assert_eq!(path("A/Report.TXT").fold_case(), "a/report.txt");
    }
}
