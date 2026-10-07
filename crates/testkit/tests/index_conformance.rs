//! The index conformance suite on the in-memory index.

#![cfg(test)]

use oxisoft_drive_testkit::MemIndex;

oxisoft_drive_testkit::index_conformance_tests!(async { (MemIndex::new(), ()) });
