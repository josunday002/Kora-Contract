#![no_std]

use soroban_sdk::{contract, contractimpl, contracttype, Address, Env};
use kora_shared::{errors::KoraError, events};

// ── TTL constants (~30 days) ──────────────────────────────────────────────────
const PERSISTENT_TTL_THRESHOLD: u32 = 518_400;
const PERSISTENT_TTL_BUMP: u32 = 518_400;

// ── Storage Keys ─────────────────────────────────────────────────────────────

#[contracttype]
pub enum DataKey {
    Admin,
    Paused,
    Role(Address),
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Role {
    Admin,
    Operator,
    Verifier,
    None,
}

// ── Contract ──────────────────────────────────────────────────────────────────

#[contract]
pub struct AccessControlContract;

#[contractimpl]
impl AccessControlContract {
    /// One-time initialization. Sets the admin and initializes the paused flag.
    pub fn initialize(env: Env, admin: Address) -> Result<(), KoraError> {
        if env.storage().instance().has(&DataKey::Admin) {
            return Err(KoraError::AlreadyInitialized);
        }
        env.storage().instance().set(&DataKey::Admin, &admin);
        env.storage().instance().set(&DataKey::Paused, &false);
        env.storage()
            .persistent()
            .set(&DataKey::Role(admin.clone()), &Role::Admin);
        Self::bump_persistent(&env, &DataKey::Role(admin));
        Ok(())
    }

    // ── Pause / Unpause ───────────────────────────────────────────────────────

    /// Pause the entire protocol. Admin only. Fails if already paused.
    pub fn pause(env: Env, admin: Address) -> Result<(), KoraError> {
        admin.require_auth();
        Self::require_admin(&env, &admin)?;
        if env
            .storage()
            .instance()
            .get::<_, bool>(&DataKey::Paused)
            .unwrap_or(false)
        {
            return Err(KoraError::AlreadyPaused);
        }
        env.storage().instance().set(&DataKey::Paused, &true);
        events::protocol_paused(&env, &admin);
        Ok(())
    }

    /// Unpause the protocol. Admin only. Fails if not currently paused.
    pub fn unpause(env: Env, admin: Address) -> Result<(), KoraError> {
        admin.require_auth();
        Self::require_admin(&env, &admin)?;
        if !env
            .storage()
            .instance()
            .get::<_, bool>(&DataKey::Paused)
            .unwrap_or(false)
        {
            return Err(KoraError::NotPaused);
        }
        env.storage().instance().set(&DataKey::Paused, &false);
        events::protocol_unpaused(&env, &admin);
        Ok(())
    }

    // ── Role management ───────────────────────────────────────────────────────

    /// Assign a role to an address. Admin only.
    /// - Cannot grant `Role::Admin` (use `transfer_admin`).
    /// - Cannot grant `Role::None` (use `revoke_role`).
    /// - Cannot grant a role to the current admin address.
    pub fn grant_role(
        env: Env,
        admin: Address,
        target: Address,
        role: Role,
    ) -> Result<(), KoraError> {
        admin.require_auth();
        Self::require_admin(&env, &admin)?;
        if role == Role::Admin {
            return Err(KoraError::Unauthorized);
        }
        if role == Role::None {
            return Err(KoraError::Unauthorized);
        }
        // Prevent silently overwriting the admin's own role entry
        if target == admin {
            return Err(KoraError::Unauthorized);
        }
        env.storage()
            .persistent()
            .set(&DataKey::Role(target.clone()), &role);
        Self::bump_persistent(&env, &DataKey::Role(target.clone()));
        events::role_granted(&env, &admin, &target);
        Ok(())
    }

    /// Revoke a role from an address. Admin only.
    /// - Cannot revoke the admin's own role.
    /// - Fails if the target has no role assigned.
    pub fn revoke_role(env: Env, admin: Address, target: Address) -> Result<(), KoraError> {
        admin.require_auth();
        Self::require_admin(&env, &admin)?;
        let current_role = env
            .storage()
            .persistent()
            .get::<_, Role>(&DataKey::Role(target.clone()))
            .unwrap_or(Role::None);
        if current_role == Role::Admin {
            return Err(KoraError::Unauthorized);
        }
        if current_role == Role::None {
            return Err(KoraError::RoleNotAssigned);
        }
        // Use remove() to reclaim storage rather than writing Role::None
        env.storage()
            .persistent()
            .remove(&DataKey::Role(target.clone()));
        events::role_revoked(&env, &admin, &target);
        Ok(())
    }

    /// Transfer admin to a new address. Current admin must sign.
    /// - Cannot transfer to self.
    /// - Cannot transfer to an address that already holds a non-None role
    ///   (would silently overwrite it). The caller must revoke first.
    pub fn transfer_admin(
        env: Env,
        current_admin: Address,
        new_admin: Address,
    ) -> Result<(), KoraError> {
        current_admin.require_auth();
        Self::require_admin(&env, &current_admin)?;
        if current_admin == new_admin {
            return Err(KoraError::InvalidAddress);
        }
        // Guard: new_admin must not already hold a role (Operator/Verifier)
        // to prevent silent role overwrite.
        let existing = env
            .storage()
            .persistent()
            .get::<_, Role>(&DataKey::Role(new_admin.clone()))
            .unwrap_or(Role::None);
        if existing != Role::None && existing != Role::Admin {
            return Err(KoraError::Unauthorized);
        }
        env.storage()
            .instance()
            .set(&DataKey::Admin, &new_admin);
        env.storage()
            .persistent()
            .set(&DataKey::Role(new_admin.clone()), &Role::Admin);
        Self::bump_persistent(&env, &DataKey::Role(new_admin.clone()));
        // Remove old admin's role entry to reclaim storage
        env.storage()
            .persistent()
            .remove(&DataKey::Role(current_admin));
        events::admin_transferred(&env, &new_admin);
        Ok(())
    }

    // ── Views ─────────────────────────────────────────────────────────────────

    pub fn is_paused(env: Env) -> bool {
        env.storage().instance().get(&DataKey::Paused).unwrap_or(false)
    }

    pub fn get_role(env: Env, address: Address) -> Role {
        env.storage()
            .persistent()
            .get(&DataKey::Role(address))
            .unwrap_or(Role::None)
    }

    pub fn get_admin(env: Env) -> Result<Address, KoraError> {
        env.storage()
            .instance()
            .get(&DataKey::Admin)
            .ok_or(KoraError::NotInitialized)
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    fn require_admin(env: &Env, caller: &Address) -> Result<(), KoraError> {
        let admin: Address = env
            .storage()
            .instance()
            .get(&DataKey::Admin)
            .ok_or(KoraError::NotInitialized)?;
        if &admin != caller {
            return Err(KoraError::NotAdmin);
        }
        Ok(())
    }

    fn bump_persistent(env: &Env, key: &DataKey) {
        env.storage()
            .persistent()
            .extend_ttl(key, PERSISTENT_TTL_THRESHOLD, PERSISTENT_TTL_BUMP);
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use soroban_sdk::{testutils::Address as _, Env};

    fn setup() -> (Env, Address, AccessControlContractClient<'static>) {
        let env = Env::default();
        env.mock_all_auths();
        let contract_id = env.register_contract(None, AccessControlContract);
        let client = AccessControlContractClient::new(&env, &contract_id);
        let admin = Address::generate(&env);
        client.initialize(&admin);
        (env, admin, client)
    }

    // ── initialize ────────────────────────────────────────────────────────────

    #[test]
    fn test_initialize_success() {
        let env = Env::default();
        env.mock_all_auths();
        let contract_id = env.register_contract(None, AccessControlContract);
        let client = AccessControlContractClient::new(&env, &contract_id);
        let admin = Address::generate(&env);
        assert!(client.try_initialize(&admin).is_ok());
        assert_eq!(client.get_admin(), admin);
        assert_eq!(client.get_role(&admin), Role::Admin);
        assert!(!client.is_paused());
    }

    #[test]
    fn test_initialize_already_initialized() {
        let (_, admin, client) = setup();
        assert!(client.try_initialize(&admin).is_err());
    }

    // ── pause / unpause ───────────────────────────────────────────────────────

    #[test]
    fn test_pause_unpause() {
        let (_, admin, client) = setup();
        assert!(!client.is_paused());
        client.pause(&admin);
        assert!(client.is_paused());
        client.unpause(&admin);
        assert!(!client.is_paused());
    }

    #[test]
    fn test_pause_already_paused() {
        let (_, admin, client) = setup();
        client.pause(&admin);
        // Second pause must fail with AlreadyPaused, not silently succeed
        let result = client.try_pause(&admin);
        assert!(result.is_err());
    }

    #[test]
    fn test_unpause_when_not_paused() {
        let (_, admin, client) = setup();
        // Unpause on a non-paused contract must fail with NotPaused
        let result = client.try_unpause(&admin);
        assert!(result.is_err());
    }

    #[test]
    fn test_non_admin_cannot_pause() {
        let (env, _, client) = setup();
        let stranger = Address::generate(&env);
        assert!(client.try_pause(&stranger).is_err());
    }

    #[test]
    fn test_non_admin_cannot_unpause() {
        let (env, admin, client) = setup();
        client.pause(&admin);
        let stranger = Address::generate(&env);
        assert!(client.try_unpause(&stranger).is_err());
    }

    #[test]
    fn test_pause_unpause_cycle_multiple_times() {
        let (_, admin, client) = setup();
        for _ in 0..3 {
            client.pause(&admin);
            assert!(client.is_paused());
            client.unpause(&admin);
            assert!(!client.is_paused());
        }
    }

    // ── grant_role ────────────────────────────────────────────────────────────

    #[test]
    fn test_grant_role_operator() {
        let (env, admin, client) = setup();
        let operator = Address::generate(&env);
        client.grant_role(&admin, &operator, &Role::Operator);
        assert_eq!(client.get_role(&operator), Role::Operator);
    }

    #[test]
    fn test_grant_role_verifier() {
        let (env, admin, client) = setup();
        let verifier = Address::generate(&env);
        client.grant_role(&admin, &verifier, &Role::Verifier);
        assert_eq!(client.get_role(&verifier), Role::Verifier);
    }

    #[test]
    fn test_grant_role_admin_forbidden() {
        // Cannot grant Role::Admin — must use transfer_admin
        let (env, admin, client) = setup();
        let target = Address::generate(&env);
        assert!(client.try_grant_role(&admin, &target, &Role::Admin).is_err());
    }

    #[test]
    fn test_grant_role_none_forbidden() {
        // Cannot grant Role::None — must use revoke_role
        let (env, admin, client) = setup();
        let target = Address::generate(&env);
        assert!(client.try_grant_role(&admin, &target, &Role::None).is_err());
    }

    #[test]
    fn test_grant_role_to_admin_self_forbidden() {
        // Admin cannot grant a role to their own address
        let (_, admin, client) = setup();
        assert!(client.try_grant_role(&admin, &admin, &Role::Operator).is_err());
    }

    #[test]
    fn test_grant_role_non_admin_forbidden() {
        let (env, _, client) = setup();
        let stranger = Address::generate(&env);
        let target = Address::generate(&env);
        assert!(client.try_grant_role(&stranger, &target, &Role::Verifier).is_err());
    }

    #[test]
    fn test_grant_role_override() {
        let (env, admin, client) = setup();
        let user = Address::generate(&env);
        client.grant_role(&admin, &user, &Role::Operator);
        assert_eq!(client.get_role(&user), Role::Operator);
        client.grant_role(&admin, &user, &Role::Verifier);
        assert_eq!(client.get_role(&user), Role::Verifier);
    }

    #[test]
    fn test_grant_role_multiple_users() {
        let (env, admin, client) = setup();
        let v1 = Address::generate(&env);
        let v2 = Address::generate(&env);
        let op = Address::generate(&env);
        client.grant_role(&admin, &v1, &Role::Verifier);
        client.grant_role(&admin, &v2, &Role::Verifier);
        client.grant_role(&admin, &op, &Role::Operator);
        assert_eq!(client.get_role(&v1), Role::Verifier);
        assert_eq!(client.get_role(&v2), Role::Verifier);
        assert_eq!(client.get_role(&op), Role::Operator);
    }

    // ── revoke_role ───────────────────────────────────────────────────────────

    #[test]
    fn test_revoke_role_success() {
        let (env, admin, client) = setup();
        let operator = Address::generate(&env);
        client.grant_role(&admin, &operator, &Role::Operator);
        assert_eq!(client.get_role(&operator), Role::Operator);
        client.revoke_role(&admin, &operator);
        assert_eq!(client.get_role(&operator), Role::None);
    }

    #[test]
    fn test_revoke_role_admin_forbidden() {
        // Cannot revoke the admin's own role
        let (_, admin, client) = setup();
        assert!(client.try_revoke_role(&admin, &admin).is_err());
    }

    #[test]
    fn test_revoke_role_not_assigned() {
        // Revoking a role from an address that has none must fail
        let (env, admin, client) = setup();
        let stranger = Address::generate(&env);
        assert!(client.try_revoke_role(&admin, &stranger).is_err());
    }

    #[test]
    fn test_revoke_role_non_admin_forbidden() {
        let (env, admin, client) = setup();
        let operator = Address::generate(&env);
        let stranger = Address::generate(&env);
        client.grant_role(&admin, &operator, &Role::Operator);
        assert!(client.try_revoke_role(&stranger, &operator).is_err());
    }

    #[test]
    fn test_revoke_then_re_grant() {
        let (env, admin, client) = setup();
        let user = Address::generate(&env);
        client.grant_role(&admin, &user, &Role::Verifier);
        client.revoke_role(&admin, &user);
        assert_eq!(client.get_role(&user), Role::None);
        // Re-granting after revoke must work
        client.grant_role(&admin, &user, &Role::Operator);
        assert_eq!(client.get_role(&user), Role::Operator);
    }

    // ── transfer_admin ────────────────────────────────────────────────────────

    #[test]
    fn test_transfer_admin_success() {
        let (env, admin, client) = setup();
        let new_admin = Address::generate(&env);
        client.transfer_admin(&admin, &new_admin);
        assert_eq!(client.get_admin(), new_admin);
        assert_eq!(client.get_role(&new_admin), Role::Admin);
        // Old admin's role entry must be removed
        assert_eq!(client.get_role(&admin), Role::None);
    }

    #[test]
    fn test_transfer_admin_to_self_forbidden() {
        let (_, admin, client) = setup();
        assert!(client.try_transfer_admin(&admin, &admin).is_err());
    }

    #[test]
    fn test_transfer_admin_non_admin_forbidden() {
        let (env, _, client) = setup();
        let stranger = Address::generate(&env);
        let new_admin = Address::generate(&env);
        assert!(client.try_transfer_admin(&stranger, &new_admin).is_err());
    }

    #[test]
    fn test_transfer_admin_to_existing_role_holder_forbidden() {
        // new_admin already has Operator role — transfer must fail to avoid silent overwrite
        let (env, admin, client) = setup();
        let operator = Address::generate(&env);
        client.grant_role(&admin, &operator, &Role::Operator);
        assert!(client.try_transfer_admin(&admin, &operator).is_err());
    }

    #[test]
    fn test_transfer_admin_to_verifier_forbidden() {
        let (env, admin, client) = setup();
        let verifier = Address::generate(&env);
        client.grant_role(&admin, &verifier, &Role::Verifier);
        assert!(client.try_transfer_admin(&admin, &verifier).is_err());
    }

    #[test]
    fn test_transfer_admin_old_admin_loses_privileges() {
        let (env, admin, client) = setup();
        let new_admin = Address::generate(&env);
        client.transfer_admin(&admin, &new_admin);
        // Old admin can no longer pause
        assert!(client.try_pause(&admin).is_err());
    }

    #[test]
    fn test_transfer_admin_new_admin_can_act() {
        let (env, admin, client) = setup();
        let new_admin = Address::generate(&env);
        client.transfer_admin(&admin, &new_admin);
        // New admin can pause
        assert!(client.try_pause(&new_admin).is_ok());
    }

    #[test]
    fn test_transfer_admin_chain() {
        // A → B → C
        let (env, admin_a, client) = setup();
        let admin_b = Address::generate(&env);
        let admin_c = Address::generate(&env);
        client.transfer_admin(&admin_a, &admin_b);
        assert_eq!(client.get_admin(), admin_b);
        client.transfer_admin(&admin_b, &admin_c);
        assert_eq!(client.get_admin(), admin_c);
        assert_eq!(client.get_role(&admin_a), Role::None);
        assert_eq!(client.get_role(&admin_b), Role::None);
        assert_eq!(client.get_role(&admin_c), Role::Admin);
    }

    // ── get_admin ─────────────────────────────────────────────────────────────

    #[test]
    fn test_get_admin_before_init_fails() {
        let env = Env::default();
        env.mock_all_auths();
        let contract_id = env.register_contract(None, AccessControlContract);
        let client = AccessControlContractClient::new(&env, &contract_id);
        assert!(client.try_get_admin().is_err());
    }

    // ── get_role ──────────────────────────────────────────────────────────────

    #[test]
    fn test_get_role_unknown_address_returns_none() {
        let (env, _, client) = setup();
        let unknown = Address::generate(&env);
        assert_eq!(client.get_role(&unknown), Role::None);
    }
}
