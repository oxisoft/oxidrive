//! The file system conformance suite on the in-memory file system, with both name rules.

#![cfg(test)]

use oxisoft_drive_core::FsRules;
use oxisoft_drive_testkit::MemFs;
use oxisoft_drive_testkit::fs_conformance::MemFolder;

mod case_sensitive {
    use super::*;

    oxisoft_drive_testkit::fs_conformance_tests!((MemFolder(MemFs::new(FsRules::default())), ()));
}

mod case_insensitive {
    use super::*;

    oxisoft_drive_testkit::fs_conformance_tests!((
        MemFolder(MemFs::new(FsRules {
            case_insensitive: true,
            windows_names: true,
        })),
        ()
    ));
}
