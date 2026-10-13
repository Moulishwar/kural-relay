//! NIP-77 (negentropy) set reconciliation is limited to relay admins.
//!
//! relay_builder answers `NEG-OPEN` straight from the database: it never calls
//! the event processor's `verify_filters` or `can_see_event`. So whatever
//! those rules hide -- gift wraps from everyone but their recipient, private
//! groups from non-members, moderation reports from non-admins, and on a
//! closed relay *everything* from anonymous connections -- a reconciliation
//! still enumerates: the ids and timestamps of every matching event. For gift
//! wraps that is exactly the metadata NIP-59 tries to hide ("who received a
//! private message, and when"); the content stays protected, because fetching
//! an id afterwards goes through the normal REQ checks.
//!
//! Reconciliation exists for operators syncing relays, so it is kept for relay
//! admins and refused to everyone else with NIP-77's `blocked:` reason, before
//! any database work.

use nostr_sdk::prelude::*;
use relay_builder::nostr_middleware::{InboundContext, NostrMiddleware};
use std::borrow::Cow;
use std::sync::Arc;

const NEGENTROPY_BLOCKED: &str = "blocked: negentropy sync is limited to relay admins";

#[derive(Debug, Clone)]
pub struct NegentropyGate {
    relay_pubkey: PublicKey,
    admin_pubkeys: Arc<Vec<PublicKey>>,
}

impl NegentropyGate {
    pub fn new(relay_pubkey: PublicKey, admin_pubkeys: Vec<PublicKey>) -> Self {
        Self {
            relay_pubkey,
            admin_pubkeys: Arc::new(admin_pubkeys),
        }
    }

    /// Only an authenticated relay admin (or the relay's own key) may reconcile.
    fn allows(&self, authed_pubkey: Option<&PublicKey>) -> bool {
        authed_pubkey.is_some_and(|pk| *pk == self.relay_pubkey || self.admin_pubkeys.contains(pk))
    }
}

impl NostrMiddleware<()> for NegentropyGate {
    async fn process_inbound<Next>(
        &self,
        ctx: InboundContext<'_, (), Next>,
    ) -> Result<(), anyhow::Error>
    where
        Next: relay_builder::nostr_middleware::InboundProcessor<()>,
    {
        let Some(ClientMessage::NegOpen {
            subscription_id, ..
        }) = ctx.message.as_ref()
        else {
            return ctx.next().await;
        };

        let authed_pubkey = ctx.state.read().await.authed_pubkey;
        if self.allows(authed_pubkey.as_ref()) {
            return ctx.next().await;
        }

        let subscription_id = subscription_id.as_ref().clone();
        ctx.send_message(RelayMessage::NegErr {
            subscription_id: Cow::Owned(subscription_id),
            message: Cow::Borrowed(NEGENTROPY_BLOCKED),
        })?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_admins_and_the_relay_may_reconcile() {
        let relay = Keys::generate().public_key();
        let admin = Keys::generate().public_key();
        let guest = Keys::generate().public_key();
        let gate = NegentropyGate::new(relay, vec![admin]);

        assert!(!gate.allows(None), "anonymous");
        assert!(!gate.allows(Some(&guest)), "an ordinary authenticated user");
        assert!(gate.allows(Some(&admin)));
        assert!(gate.allows(Some(&relay)));
    }

    #[test]
    fn the_refusal_uses_the_nip77_blocked_reason() {
        assert!(NEGENTROPY_BLOCKED.starts_with("blocked: "));
    }
}
