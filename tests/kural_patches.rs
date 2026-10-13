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
    groups: Arc<Groups>,
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
    /// The relay as upstream ships it: the whitelist gates reads and writes.
    async fn new() -> Self {
        Self::build(false).await
    }

    /// Kural's configuration: `public_read: true`.
    async fn public_read() -> Self {
        Self::build(true).await
    }

    async fn build(public_read: bool) -> Self {
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
        let processor = GroupsRelayProcessor::new(groups.clone(), relay.public_key(), whitelist)
            .with_public_read(public_read);
        Self {
            _tmp: tmp,
            groups,
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

    async fn publish(&self, who: Option<&Keys>, event: Event) -> relay_builder::Result<()> {
        self.processor
            .handle_event(event, state(), &self.as_user(who))
            .await
            .map(|_| ())
    }

    /// A managed NIP-29 group created by Ravi. `flags` are the 9007 tags,
    /// e.g. `["public", "open"]` or `["private"]`.
    async fn create_group(&self, id: &str, flags: &[&str]) {
        let mut builder =
            EventBuilder::new(Kind::Custom(9007), "").tag(Tag::custom(TagKind::h(), [id]));
        for flag in flags {
            builder = builder.tag(Tag::custom(
                TagKind::Custom((*flag).into()),
                Vec::<String>::new(),
            ));
        }
        let event = builder.sign_with_keys(&self.ravi).unwrap();
        self.groups
            .handle_group_create(Box::new(event), &Scope::Default)
            .await
            .unwrap();
    }
}

fn state() -> Arc<RwLock<()>> {
    Arc::new(RwLock::new(()))
}

fn is_auth_required(r: &relay_builder::Result<()>) -> bool {
    matches!(r, Err(relay_builder::Error::AuthRequired { .. }))
}

fn is_restricted(r: &relay_builder::Result<()>) -> bool {
    matches!(r, Err(relay_builder::Error::Restricted { .. }))
}

fn note(author: &Keys) -> Event {
    EventBuilder::text_note("hello")
        .sign_with_keys(author)
        .unwrap()
}

fn in_group(author: &Keys, kind: u16, group: &str) -> Event {
    EventBuilder::new(Kind::Custom(kind), "post")
        .tag(Tag::custom(TagKind::h(), [group]))
        .sign_with_keys(author)
        .unwrap()
}

/// Marmot group traffic: kind 445, a fresh signing key, an unmanaged `h`.
fn marmot_445(group: &str) -> Event {
    in_group(&Keys::generate(), 445, group)
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

// ---------------------------------------------------------------- patch (b): public_read

#[tokio::test]
async fn b1_anyone_can_read_public_notes() {
    let f = Fixture::public_read().await;
    assert!(f
        .verify(None, vec![Filter::new().kind(Kind::TextNote)])
        .is_ok());
    assert!(f.sees(None, &note(&f.ravi)));
}

#[tokio::test]
async fn b2_anyone_can_read_a_public_group() {
    let f = Fixture::public_read().await;
    f.create_group("town-square", &["public", "open"]).await;
    let filter = Filter::new().custom_tag(SingleLetterTag::lowercase(Alphabet::H), "town-square");
    assert!(f.verify(None, vec![filter]).is_ok());
    assert!(f.sees(None, &in_group(&f.ravi, 11, "town-square")));
}

#[tokio::test]
async fn b3_a_private_group_stays_members_only() {
    let f = Fixture::public_read().await;
    f.create_group("family", &["private"]).await;
    let filter = Filter::new().custom_tag(SingleLetterTag::lowercase(Alphabet::H), "family");
    assert!(is_auth_required(&f.verify(None, vec![filter.clone()])));
    assert!(is_restricted(&f.verify(Some(&f.outsider), vec![filter])));
    let post = in_group(&f.ravi, 11, "family");
    assert!(!f.sees(None, &post));
    assert!(
        !f.sees(Some(&f.meera), &post),
        "a guest who is not a member"
    );
}

#[tokio::test]
async fn b4_anonymous_request_for_private_traffic_is_told_to_authenticate() {
    let f = Fixture::public_read().await;
    let filter = Filter::new()
        .kind(Kind::Custom(445))
        .custom_tag(SingleLetterTag::lowercase(Alphabet::H), "abc");
    assert!(is_auth_required(&f.verify(None, vec![filter])));
}

#[tokio::test]
async fn b5_a_logged_in_non_guest_is_refused_private_traffic() {
    let f = Fixture::public_read().await;
    let filter = Filter::new().kind(Kind::Custom(445));
    assert!(is_restricted(&f.verify(Some(&f.outsider), vec![filter])));
    assert!(!f.sees(Some(&f.outsider), &marmot_445("abc")));
}

#[tokio::test]
async fn b6_a_guest_reads_private_traffic() {
    let f = Fixture::public_read().await;
    let filter = Filter::new().kind(Kind::Custom(445));
    assert!(f.verify(Some(&f.meera), vec![filter]).is_ok());
    assert!(f.sees(Some(&f.meera), &marmot_445("abc")));
}

#[tokio::test]
async fn b7_an_empty_filter_returns_public_events_only() {
    let f = Fixture::public_read().await;
    assert!(f.verify(None, vec![Filter::new()]).is_ok());
    assert!(f.sees(None, &note(&f.ravi)));
    assert!(!f.sees(None, &marmot_445("abc")));
    assert!(!f.sees(None, &gift_wrap_to(&f.ravi)));
    assert!(!f.sees(None, &report_against(&f.ravi, &f.meera)));
    // The same for a logged-in non-guest, and for a `#h` filter that never names 445.
    let by_group = Filter::new().custom_tag(SingleLetterTag::lowercase(Alphabet::H), "abc");
    assert!(f.verify(Some(&f.outsider), vec![by_group]).is_ok());
    assert!(!f.sees(Some(&f.outsider), &marmot_445("abc")));
}

#[tokio::test]
async fn b8_anonymous_writes_are_still_told_to_authenticate() {
    let f = Fixture::public_read().await;
    let r = f.publish(None, note(&f.ravi)).await;
    assert!(is_auth_required(&r), "got {r:?}");
}

#[tokio::test]
async fn b9_a_logged_in_non_guest_still_cannot_write() {
    let f = Fixture::public_read().await;
    let r = f.publish(Some(&f.outsider), note(&f.outsider)).await;
    assert!(is_restricted(&r), "got {r:?}");
    // Guests can.
    assert!(f.publish(Some(&f.ravi), note(&f.ravi)).await.is_ok());
}

#[tokio::test]
async fn b10_reports_stay_admin_only() {
    let f = Fixture::public_read().await;
    let filter = Filter::new().kind(Kind::Reporting);
    assert!(f.verify(Some(&f.ravi), vec![filter.clone()]).is_err());
    assert!(f.verify(None, vec![filter.clone()]).is_err());
    assert!(f.verify(Some(&f.relay), vec![filter]).is_ok());
}

#[tokio::test]
async fn b11_without_public_read_the_whitelist_still_gates_reads() {
    let f = Fixture::new().await;
    f.create_group("town-square", &["public", "open"]).await;
    assert!(is_auth_required(
        &f.verify(None, vec![Filter::new().kind(Kind::TextNote)])
    ));
    let by_group = Filter::new().custom_tag(SingleLetterTag::lowercase(Alphabet::H), "town-square");
    assert!(is_auth_required(&f.verify(None, vec![by_group])));
    assert!(is_auth_required(
        &f.verify(Some(&f.outsider), vec![Filter::new()])
    ));
    assert!(f.verify(Some(&f.ravi), vec![Filter::new()]).is_ok());
}

#[tokio::test]
async fn b12_a_non_guest_recipient_does_not_get_gift_wraps_on_a_public_read_relay() {
    let f = Fixture::public_read().await;
    // Only guests take part in private spaces; a wrap addressed to an
    // outsider stays on the relay but is not served to them.
    let wrap = gift_wrap_to(&f.outsider);
    assert!(!f.sees(Some(&f.outsider), &wrap));
    assert!(f.sees(Some(&f.ravi), &gift_wrap_to(&f.ravi)));
}
