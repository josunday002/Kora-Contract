use soroban_sdk::{contracttype, Env};
use crate::errors::KoraError;

/// Storage key for the reentrancy lock.
///
/// Stored in `instance()` storage so it is scoped to the contract instance
/// and cleared automatically when the transaction ends (no persistent bleed).
#[contracttype]
pub enum GuardKey {
    /// Active reentrancy lock flag.
    Lock,
}

// ── Low-level helpers ─────────────────────────────────────────────────────────

/// Acquire the reentrancy lock.
///
/// Returns `KoraError::Reentrant` if the lock is already held, preventing
/// any recursive (reentrant) call from proceeding.
pub fn acquire_guard(env: &Env) -> Result<(), KoraError> {
    if env.storage().instance().has(&GuardKey::Lock) {
        return Err(KoraError::Reentrant);
    }
    env.storage().instance().set(&GuardKey::Lock, &true);
    Ok(())
}

/// Release the reentrancy lock.
///
/// Must be called on every exit path of a protected function.
/// Prefer [`ReentrancyGuard`] which handles this automatically.
pub fn release_guard(env: &Env) {
    env.storage().instance().remove(&GuardKey::Lock);
}

/// Returns `true` if the reentrancy lock is currently held.
pub fn is_locked(env: &Env) -> bool {
    env.storage().instance().has(&GuardKey::Lock)
}

// ── RAII guard ────────────────────────────────────────────────────────────────

/// RAII-style reentrancy guard.
///
/// Acquires the lock on construction and releases it when dropped, ensuring
/// the lock is always freed even if the protected function returns early via `?`.
///
/// # Usage
/// ```ignore
/// pub fn sensitive_fn(env: Env) -> Result<(), KoraError> {
///     let _guard = ReentrancyGuard::new(&env)?;
///     // ... protected logic ...
///     Ok(())
/// } // lock released here automatically
/// ```
pub struct ReentrancyGuard<'a> {
    env: &'a Env,
}

impl<'a> ReentrancyGuard<'a> {
    /// Attempt to acquire the reentrancy lock.
    ///
    /// Returns `Err(KoraError::Reentrant)` if the lock is already held.
    pub fn new(env: &'a Env) -> Result<Self, KoraError> {
        acquire_guard(env)?;
        Ok(ReentrancyGuard { env })
    }
}

impl<'a> Drop for ReentrancyGuard<'a> {
    fn drop(&mut self) {
        release_guard(self.env);
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use soroban_sdk::Env;

    #[test]
    fn test_acquire_succeeds_when_unlocked() {
        let env = Env::default();
        assert!(acquire_guard(&env).is_ok());
        release_guard(&env);
    }

    #[test]
    fn test_acquire_fails_when_locked() {
        let env = Env::default();
        acquire_guard(&env).unwrap();
        let result = acquire_guard(&env);
        assert_eq!(result.unwrap_err(), KoraError::Reentrant);
        release_guard(&env);
    }

    #[test]
    fn test_release_allows_reacquire() {
        let env = Env::default();
        acquire_guard(&env).unwrap();
        release_guard(&env);
        assert!(acquire_guard(&env).is_ok());
        release_guard(&env);
    }

    #[test]
    fn test_is_locked_reflects_state() {
        let env = Env::default();
        assert!(!is_locked(&env));
        acquire_guard(&env).unwrap();
        assert!(is_locked(&env));
        release_guard(&env);
        assert!(!is_locked(&env));
    }

    #[test]
    fn test_raii_guard_releases_on_drop() {
        let env = Env::default();
        {
            let _guard = ReentrancyGuard::new(&env).unwrap();
            assert!(is_locked(&env));
            // Second acquisition must fail
            assert_eq!(
                ReentrancyGuard::new(&env).unwrap_err(),
                KoraError::Reentrant
            );
        }
        // Lock must be released after the guard is dropped
        assert!(!is_locked(&env));
        assert!(ReentrancyGuard::new(&env).is_ok());
    }

    #[test]
    fn test_raii_guard_releases_on_early_return() {
        let env = Env::default();

        fn protected(env: &Env) -> Result<(), KoraError> {
            let _guard = ReentrancyGuard::new(env)?;
            // Simulate early return via ?
            Err(KoraError::InvalidAmount)
        }

        let _ = protected(&env);
        // Lock must be released even after early return
        assert!(!is_locked(&env));
    }
}
