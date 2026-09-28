use std::future::Future;
use std::sync::Mutex;

use oxisoft_drive_core::{IndexError, IndexState, IndexStore, IndexTxn};

/// A transactional in-memory index. Share it through `Arc` and drop the engine to simulate a
/// crash: the index keeps exactly the transactions that completed.
#[derive(Debug, Default)]
pub struct MemIndex {
    state: Mutex<IndexState>,
    fail_applies: Mutex<usize>,
    /// Successful transactions left before one fails.
    fail_after: Mutex<Option<usize>>,
}

impl MemIndex {
    /// An empty index.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// The stored state.
    #[must_use]
    pub fn snapshot(&self) -> IndexState {
        lock(&self.state).clone()
    }

    /// Lets `count` transactions through, then fails one.
    pub fn fail_apply_after(&self, count: usize) {
        *lock(&self.fail_after) = Some(count);
    }

    /// Cancels every injected failure that hasn't fired.
    pub fn cancel_failures(&self) {
        *lock(&self.fail_after) = None;
        *lock(&self.fail_applies) = 0;
    }

    /// Makes the next `count` transactions fail without applying.
    pub fn fail_next_applies(&self, count: usize) {
        *lock(&self.fail_applies) = count;
    }
}

fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

impl IndexStore for MemIndex {
    fn load(&self) -> impl Future<Output = Result<IndexState, IndexError>> + Send {
        std::future::ready(Ok(self.snapshot()))
    }

    fn apply(&self, txn: IndexTxn) -> impl Future<Output = Result<(), IndexError>> + Send {
        std::future::ready(self.apply_now(&txn))
    }
}

impl MemIndex {
    fn apply_now(&self, txn: &IndexTxn) -> Result<(), IndexError> {
        let mut countdown = lock(&self.fail_after);
        if let Some(left) = countdown.as_mut() {
            if *left == 0 {
                *countdown = None;
                return Err(IndexError("injected failure".into()));
            }
            *left -= 1;
        }
        drop(countdown);
        let mut failures = lock(&self.fail_applies);
        if *failures > 0 {
            *failures -= 1;
            return Err(IndexError("injected failure".into()));
        }
        txn.apply_to(&mut lock(&self.state));
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::block_on;

    #[test]
    fn applies_transactions_atomically_and_fails_on_request() {
        let index = MemIndex::new();
        let txn = IndexTxn {
            counter: Some(4),
            ..IndexTxn::default()
        };
        block_on(index.apply(txn.clone())).unwrap();
        assert_eq!(block_on(index.load()).unwrap().counter, 4);
        index.fail_next_applies(1);
        let later = IndexTxn {
            counter: Some(9),
            ..IndexTxn::default()
        };
        assert!(block_on(index.apply(later.clone())).is_err());
        assert_eq!(index.snapshot().counter, 4);
        block_on(index.apply(later)).unwrap();
        assert_eq!(index.snapshot().counter, 9);
    }
}
