//! Static role → action policy table, evaluated per request (mirrors the
//! reference `POLICY`).

/// Actions allowed for `owner`.
pub const OWNER_ACTIONS: &[&str] = &[
    "echo",
    "portal.open",
    "hermes.config.read",
    "portal.publish",
];
/// Actions allowed for `guest`.
pub const GUEST_ACTIONS: &[&str] = &["echo", "portal.view"];

/// Whether `role` may perform `act`. Unknown roles/actions are denied.
pub fn action_allowed(role: &str, act: &str) -> bool {
    let table = match role {
        "owner" => OWNER_ACTIONS,
        "guest" => GUEST_ACTIONS,
        _ => return false,
    };
    table.contains(&act)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn policy_table() {
        assert!(action_allowed("owner", "portal.publish"));
        assert!(action_allowed("owner", "hermes.config.read"));
        assert!(action_allowed("guest", "echo"));
        assert!(!action_allowed("guest", "portal.publish"));
        assert!(!action_allowed("guest", "hermes.config.read"));
        assert!(!action_allowed("owner", "teleport.moon"));
        assert!(!action_allowed("outsider", "echo"));
    }
}
