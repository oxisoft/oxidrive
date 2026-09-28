//! oxidrive test support: in-memory implementations of every engine trait, with failure
//! injection, and a minimal executor for running the async engine in tests.
//!
//! - [`MemFs`]: a file system with file IDs, times, executable bits, optional case-insensitive
//!   names and Windows name rules, and injectable failures.
//! - [`MemServer`]: collections with compare-and-swap commit logs and a chunk store, shareable
//!   between devices, with injectable failures (including "applied, but the answer was lost").
//! - [`MemIndex`]: a transactional index that survives a simulated crash.
//! - [`ManualClock`]: time set by the test.
//! - [`World`]: one server, clock and collection shared by several test devices.
//! - [`block_on`]: runs a future to completion on the current thread.

mod clock;
mod fs;
mod index;
mod server;
mod world;

use std::future::Future;
use std::pin::pin;
use std::sync::Arc;
use std::task::{Context, Poll, Wake, Waker};
use std::thread::{self, Thread};

pub use clock::ManualClock;
pub use fs::{FsOp, MemFs, UserAction};
pub use index::MemIndex;
pub use server::{MemServer, ServerFailure, ServerOp};
pub use world::{Device, DeviceEngine, Tree, World, contents};

/// Runs `future` to completion on the current thread. In-memory implementations complete
/// immediately, so tests stay deterministic.
pub fn block_on<F: Future>(future: F) -> F::Output {
    struct Unpark(Thread);

    impl Wake for Unpark {
        fn wake(self: Arc<Self>) {
            self.0.unpark();
        }
    }

    let waker = Waker::from(Arc::new(Unpark(thread::current())));
    let mut context = Context::from_waker(&waker);
    let mut future = pin!(future);
    loop {
        if let Poll::Ready(output) = future.as_mut().poll(&mut context) {
            return output;
        }
        thread::park();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn runs_ready_and_pending_futures() {
        assert_eq!(block_on(async { 7 }), 7);
        // A future that is pending once and wakes itself.
        let mut polled = false;
        let yield_once = std::future::poll_fn(|cx| {
            if polled {
                Poll::Ready("done")
            } else {
                polled = true;
                cx.waker().wake_by_ref();
                Poll::Pending
            }
        });
        assert_eq!(block_on(yield_once), "done");
    }
}
