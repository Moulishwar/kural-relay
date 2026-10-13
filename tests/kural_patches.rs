//! Kural patches to obelisk-relay: access rules, checked at the processor.
//!
//! `verify_filters` decides whether a REQ may run at all; `can_see_event`
//! decides, per event, what it may return -- for stored results and live
//! broadcasts alike (relay_builder applies it on both paths). The test ids
//! (a1…, b1…) match Kural's `Docs/Plan/Slice_01_Relay_Patches.md`.

use groups_relay::{
    blacklist::Blacklist, groups::Groups, groups_event_processor::GroupsRelayProcessor,
    whitelist::Whitelist, RelayDatabase,
};
use nostr_lmdb::Scope;
use nostr_sdk::prelude::*;
use relay_builder::{EventContext, EventProcessor};
use std::sync::Arc;
use tempfile::TempDir;
use tokio::sync::RwLock;

struct Fixture {
    _tmp: TempDir,
    processor: GroupsRelayProcessor,
    relay: Keys,
    /// On the guest list.
    ravi: Keys,
    /// On the guest list.
    meera: Keys,
    /// Authenticated, but not on the guest list.
    outsider: Keys,
}

impl Fixture {
    async fn new() -> Self {
        let tmp = TempDir::new().unwrap();
        let database = Arc::new(
            RelayDatabase::new(tmp.path().join("test.db").to_str().unwrap())
                .await
                .unwrap(),
        );
        let relay = Keys::generate();
        let (ravi, meera, outsider) = (Keys::generate(), Keys::generate(), Keys::generate());
        let groups = Arc::new(
            Groups::load_groups(
                database,
                relay.public_key(),
                "wss://kural.test".to_string(),
                false,
            )
            .await
            .unwrap(),
        );
        let whitelist = Whitelist::new(
            vec![ravi.public_key(), meera.public_key()],
            None,
            Blacklist::new(None),
        );
        let processor = GroupsRelayProcessor::new(groups, relay.public_key(), whitelist);
        Self {
            _tmp: tmp,
            processor,
            relay,
            ravi,
            meera,
            outsider,
        }
    }

    fn as_user(&self, who: Option<&Keys>) -> EventContext {
        EventContext {
            authed_pubkey: who.map(|k| k.public_key()),
            subdomain: Arc::new(Scope::Default),
            relay_pubkey: self.relay.public_key(),
        }
    }

    fn verify(&self, who: Option<&Keys>, filters: Vec<Filter>) -> relay_builder::Result<()> {
        self.processor
            .verify_filters(&filters, state(), &self.as_user(who))
    }

    fn sees(&self, who: Option<&Keys>, event: &Event) -> bool {
        self.processor
            .can_see_event(event, state(), &self.as_user(who))
            .unwrap_or(false)
    }
}

fn state() -> Arc<RwLock<()>> {
    Arc::new(RwLock::new(()))
}

fn is_auth_required(r: &relay_builder::Result<()>) -> bool {
    matches!(r, Err(relay_builder::Error::AuthRequired { .. }))
}

/// A gift wrap as Marmot / NIP-59 publish it: signed by a throwaway key,
/// naming only its recipient.
fn gift_wrap_to(recipient: &Keys) -> Event {
    EventBuilder::new(Kind::GiftWrap, "ciphertext")
        .tag(Tag::public_key(recipient.public_key()))
        .sign_with_keys(&Keys::generate())
        .unwrap()
}

// ---------------------------------------------------------------- patch (a)

#[tokio::test]
async fn a1_anonymous_request_for_gift_wraps_is_told_to_authenticate() {
    let f = Fixture::new().await;
    let r = f.verify(
        None,
        vec![Filter::new()
            .kind(Kind::GiftWrap)
            .pubkey(f.ravi.public_key())],
    );
    assert!(is_auth_required(&r), "expected auth-required, got {r:?}");
}

#[tokio::test]
async fn a2_the_recipient_receives_their_gift_wrap() {
    let f = Fixture::new().await;
    let wrap = gift_wrap_to(&f.ravi);
    let filter = Filter::new()
        .kind(Kind::GiftWrap)
        .pubkey(f.ravi.public_key());
    assert!(f.verify(Some(&f.ravi), vec![filter]).is_ok());
    assert!(f.sees(Some(&f.ravi), &wrap));
}

#[tokio::test]
async fn a3_another_guest_does_not_receive_it() {
    let f = Fixture::new().await;
    let wrap = gift_wrap_to(&f.ravi);
    let filter = Filter::new()
        .kind(Kind::GiftWrap)
        .pubkey(f.ravi.public_key());
    // The REQ itself is allowed (Meera is a guest); the wrap is withheld.
    assert!(f.verify(Some(&f.meera), vec![filter]).is_ok());
    assert!(!f.sees(Some(&f.meera), &wrap));
}

#[tokio::test]
async fn a4_a_filter_that_never_names_the_kind_cannot_reach_it() {
    let f = Fixture::new().await;
    let wrap = gift_wrap_to(&f.ravi);
    // `#p`-only: no kinds, so the explicit-kind check in verify_filters does not fire.
    assert!(f
        .verify(
            Some(&f.meera),
            vec![Filter::new().pubkey(f.ravi.public_key())]
        )
        .is_ok());
    assert!(!f.sees(Some(&f.meera), &wrap));
    // Nor by id, nor anonymously.
    assert!(!f.sees(None, &wrap));
    assert!(!f.sees(Some(&f.outsider), &wrap));
    // The relay operator is not the recipient either.
    assert!(!f.sees(Some(&f.relay), &wrap));
}

#[tokio::test]
async fn a5_a_wrap_to_several_recipients_reaches_each_of_them() {
    let f = Fixture::new().await;
    let wrap = EventBuilder::new(Kind::GiftWrap, "ciphertext")
        .tag(Tag::public_key(f.ravi.public_key()))
        .tag(Tag::public_key(f.meera.public_key()))
        .sign_with_keys(&Keys::generate())
        .unwrap();
    assert!(f.sees(Some(&f.ravi), &wrap));
    assert!(f.sees(Some(&f.meera), &wrap));
    assert!(!f.sees(Some(&f.outsider), &wrap));
}

// ---------------------------------------------------------------- reports (1984)

/// A NIP-56 report against `target`, filed by `reporter`.
fn report_against(target: &Keys, reporter: &Keys) -> Event {
    EventBuilder::new(Kind::Reporting, "spam")
        .tag(Tag::public_key(target.public_key()))
        .sign_with_keys(reporter)
        .unwrap()
}

#[tokio::test]
async fn r1_a_reported_guest_cannot_find_reports_by_asking_for_everything_about_them() {
    let f = Fixture::new().await;
    let report = report_against(&f.ravi, &f.meera);
    // `#p`-only: never names kind 1984, so the REQ-level check does not fire...
    assert!(f
        .verify(
            Some(&f.ravi),
            vec![Filter::new().pubkey(f.ravi.public_key())]
        )
        .is_ok());
    // ...but the report itself is withheld, so the reporter stays unknown.
    assert!(!f.sees(Some(&f.ravi), &report));
    assert!(!f.sees(Some(&f.meera), &report), "not even its author");
    assert!(!f.sees(Some(&f.outsider), &report));
    assert!(!f.sees(None, &report));
}

#[tokio::test]
async fn r2_relay_admins_still_see_reports() {
    let f = Fixture::new().await;
    let report = report_against(&f.ravi, &f.meera);
    assert!(f.sees(Some(&f.relay), &report));
}
