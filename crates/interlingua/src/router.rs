//! The label-based router.
//!
//! One `Router` serves one domain (its `node`). For each envelope it either
//! delivers (the node is the destination), forwards to the next hop, or
//! rejects with a [`Reason`], and it writes one audit line per decision.
//! Checks run in a fixed order (`docs/SPECIFICATION.md` §7), cheapest and most
//! fundamental first, and state (replay cache, rate tokens) changes only for
//! messages that pass every check:
//!
//! 1. decode (strict CBOR, schema, version, suite);
//! 2. both domains exist; the arrival edge exists and permits the message;
//! 3. signature by a key bound to the source domain;
//! 4. freshness (clock skew, expiry, lifetime) and hop-count integrity;
//! 5. label rules: the source may originate it, the destination is cleared
//!    for it (Bell–LaPadula), it meets the destination's integrity floor
//!    (Biba), compartments are held on both ends;
//! 6. sealing is present where required and addressed to the destination;
//! 7. a path exists whose every edge and relay permits the label, within the
//!    remaining hops (breadth-first, ties broken by domain name);
//! 8. replay cache, then the source's rate allowance.

use std::collections::{BTreeMap, BTreeSet, HashMap, VecDeque};
use std::sync::{Mutex, PoisonError};

use crate::audit::AuditChain;
use crate::crypto::sha384;
use crate::envelope::{Envelope, Header};
use crate::error::{Error, Reason};
use crate::keys::Keyring;
use crate::label::Label;
use crate::policy::{Domain, Policy, Route};
use crate::{hex, uuid7};

/// What the router did with a message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    /// This node is the destination.
    Deliver,
    /// Send the forwarded envelope to `next_hop`.
    Forward {
        /// The next domain on the path.
        next_hop: String,
    },
    /// Refused.
    Reject(Reason),
}

impl Verdict {
    /// `deliver`, `forward` or `reject`.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Deliver => "deliver",
            Self::Forward { .. } => "forward",
            Self::Reject(_) => "reject",
        }
    }
}

/// The outcome of routing one envelope.
#[derive(Debug, Clone)]
pub struct Decision {
    /// Deliver, forward or reject.
    pub verdict: Verdict,
    /// The audit line written for this decision.
    pub audit_line: String,
    /// The envelope to send on (hop count decremented) when forwarding.
    pub forwarded: Option<Vec<u8>>,
    /// The decoded envelope, if it decoded (unverified when rejected early).
    pub envelope: Option<Envelope>,
}

impl Decision {
    /// Whether the message was delivered or forwarded.
    #[must_use]
    pub fn accepted(&self) -> bool {
        !matches!(self.verdict, Verdict::Reject(_))
    }
}

#[derive(Debug)]
struct Bucket {
    milli_tokens: u64,
    last_ms: u64,
}

#[derive(Debug, Default)]
struct State {
    seen: HashMap<[u8; uuid7::LEN], u64>,
    expiry_order: BTreeSet<(u64, [u8; uuid7::LEN])>,
    buckets: HashMap<String, Bucket>,
    audit: AuditChain,
}

impl State {
    fn purge(&mut self, now: u64) {
        while let Some(&(expiry, id)) = self.expiry_order.first() {
            if expiry >= now {
                break;
            }
            self.expiry_order.remove(&(expiry, id));
            self.seen.remove(&id);
        }
    }

    fn remember(&mut self, id: [u8; uuid7::LEN], expiry: u64) {
        self.seen.insert(id, expiry);
        self.expiry_order.insert((expiry, id));
    }

    fn take_token(&mut self, src: &str, rate: u64, burst: u64, now: u64) -> bool {
        let capacity = burst.saturating_mul(1000);
        let bucket = self.buckets.entry(src.to_owned()).or_insert(Bucket {
            milli_tokens: capacity,
            last_ms: now,
        });
        if now > bucket.last_ms {
            // `rate` tokens per second is `rate` milli-tokens per millisecond.
            let refill = (now - bucket.last_ms).saturating_mul(rate);
            bucket.milli_tokens = bucket.milli_tokens.saturating_add(refill).min(capacity);
            bucket.last_ms = now;
        }
        if bucket.milli_tokens >= 1000 {
            bucket.milli_tokens -= 1000;
            true
        } else {
            false
        }
    }
}

/// A router for one domain. Thread-safe: decisions are serialized internally.
#[derive(Debug)]
pub struct Router {
    policy: Policy,
    keyring: Keyring,
    node: String,
    state: Mutex<State>,
}

fn can_hold(domain: &Domain, label: &Label) -> bool {
    label.confidentiality <= domain.confidentiality
        && label.integrity >= domain.integrity_floor
        && label.compartments.is_subset(&domain.compartments)
}

fn edge_allows(route: &Route, header: &Header) -> bool {
    header.label.confidentiality <= route.max_confidentiality
        && header.label.compartments.is_subset(&route.compartments)
        && (header.sealed || !route.sealed_required)
}

impl Router {
    /// A router for `node`, which must be a domain in `policy`.
    ///
    /// # Errors
    /// [`Error::Policy`] if `node` is not in the policy.
    pub fn new(policy: Policy, keyring: Keyring, node: &str) -> Result<Self, Error> {
        if policy.domain(node).is_none() {
            return Err(Error::Policy {
                line: 0,
                message: format!("router node `{node}` is not a domain in the policy"),
            });
        }
        Ok(Self {
            policy,
            keyring,
            node: node.to_owned(),
            state: Mutex::new(State::default()),
        })
    }

    /// The domain this router serves.
    #[must_use]
    pub fn node(&self) -> &str {
        &self.node
    }

    /// The policy in force.
    #[must_use]
    pub fn policy(&self) -> &Policy {
        &self.policy
    }

    /// Continue an audit chain from a previous run.
    pub fn resume_audit(&self, seq: u64, head: [u8; 48]) {
        self.lock().audit = AuditChain::resume(seq, head);
    }

    /// Sequence number and hash of the last audit line.
    #[must_use]
    pub fn audit_head(&self) -> (u64, [u8; 48]) {
        let state = self.lock();
        (state.audit.seq(), state.audit.head())
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, State> {
        // A panic while holding the lock leaves no half-applied decision
        // (state changes are the last steps), so the state stays usable.
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Route one envelope that arrived from `arrived_from` (`None`: it was
    /// handed to this node by a local sender) at time `now_ms`.
    #[must_use]
    pub fn route(&self, bytes: &[u8], arrived_from: Option<&str>, now_ms: u64) -> Decision {
        let mut state = self.lock();
        let mut decoded = None;
        let mut verified = false;
        let outcome = self.evaluate(
            &mut state,
            bytes,
            arrived_from,
            now_ms,
            &mut decoded,
            &mut verified,
        );
        let (verdict, forwarded) = match outcome {
            Ok(accepted) => accepted,
            Err(reason) => (Verdict::Reject(reason), None),
        };
        let header = decoded.as_ref().map(|e: &Envelope| &e.header);
        let text = |f: &dyn Fn(&Header) -> String| header.map_or_else(|| "-".to_owned(), f);
        let (reason, code) = match &verdict {
            Verdict::Reject(r) => (r.name().to_owned(), r.code().to_string()),
            _ => ("ok".to_owned(), "0".to_owned()),
        };
        let audit_line = state.audit.append(&[
            ("time", now_ms.to_string()),
            ("node", self.node.clone()),
            ("from", arrived_from.unwrap_or("-").to_owned()),
            ("id", text(&|h| uuid7::format(&h.id))),
            ("src", text(&|h| h.src.clone())),
            ("dst", text(&|h| h.dst.clone())),
            ("conf", text(&|h| h.label.confidentiality.to_string())),
            ("integ", text(&|h| h.label.integrity.to_string())),
            ("avail", text(&|h| h.label.availability.to_string())),
            (
                "comp",
                text(&|h| {
                    h.label
                        .compartments
                        .iter()
                        .cloned()
                        .collect::<Vec<_>>()
                        .join(",")
                }),
            ),
            (
                "sealed",
                text(&|h| String::from(if h.sealed { "yes" } else { "no" })),
            ),
            (
                "auth",
                String::from(if verified { "verified" } else { "unverified" }),
            ),
            ("bytes", bytes.len().to_string()),
            ("env", format!("sha384:{}", hex::encode(&sha384(bytes)))),
            ("verdict", verdict.as_str().to_owned()),
            (
                "next",
                match &verdict {
                    Verdict::Forward { next_hop } => next_hop.clone(),
                    _ => "-".to_owned(),
                },
            ),
            ("reason", reason),
            ("code", code),
        ]);
        Decision {
            verdict,
            audit_line,
            forwarded,
            envelope: decoded,
        }
    }

    fn evaluate(
        &self,
        state: &mut State,
        bytes: &[u8],
        arrived_from: Option<&str>,
        now: u64,
        decoded: &mut Option<Envelope>,
        verified: &mut bool,
    ) -> Result<(Verdict, Option<Vec<u8>>), Reason> {
        let policy = &self.policy;
        let env = decoded.insert(Envelope::decode(bytes).map_err(|_| Reason::Malformed)?);
        let h = &env.header;
        let src = policy.domain(&h.src).ok_or(Reason::UnknownSourceDomain)?;
        let dst = policy
            .domain(&h.dst)
            .ok_or(Reason::UnknownDestinationDomain)?;

        match arrived_from {
            None if h.src != self.node => return Err(Reason::UnexpectedArrival),
            None => {}
            Some(previous) => {
                let edge = policy
                    .route(previous, &self.node)
                    .ok_or(Reason::UnexpectedArrival)?;
                if !edge_allows(edge, h) || bytes.len() > edge.max_bytes {
                    return Err(Reason::UnexpectedArrival);
                }
            }
        }

        match env.verify(&self.keyring) {
            Ok(_) => *verified = true,
            Err(Error::UnknownSigner) => return Err(Reason::UnknownSigner),
            Err(Error::SignerNotAuthorized) => return Err(Reason::SignerNotAuthorized),
            Err(_) => return Err(Reason::BadSignature),
        }

        if h.created_ms > now.saturating_add(policy.clock_skew_ms) {
            return Err(Reason::NotYetValid);
        }
        if now > h.expires_ms.saturating_add(policy.clock_skew_ms) {
            return Err(Reason::Expired);
        }
        if h.expires_ms - h.created_ms > policy.max_lifetime_ms {
            return Err(Reason::LifetimeTooLong);
        }
        if env.hops > h.max_hops {
            return Err(Reason::HopCountInflated);
        }

        let label = &h.label;
        if label.confidentiality > src.confidentiality {
            return Err(Reason::ConfidentialityExceedsSource);
        }
        if label.integrity > src.integrity {
            return Err(Reason::IntegrityExceedsSource);
        }
        if label.confidentiality > dst.confidentiality {
            return Err(Reason::ConfidentialityExceedsDestination);
        }
        if label.integrity < dst.integrity_floor {
            return Err(Reason::IntegrityBelowFloor);
        }
        if !label.compartments.is_subset(&src.compartments)
            || !label.compartments.is_subset(&dst.compartments)
        {
            return Err(Reason::CompartmentNotPermitted);
        }

        if (label.confidentiality >= policy.seal_at || dst.sealed_required) && !h.sealed {
            return Err(Reason::EncryptionRequired);
        }
        if h.sealed {
            let recipient = env.sealed_recipient().map_err(|_| Reason::Malformed)?;
            match self.keyring.recipient(&recipient) {
                Some(keys) if keys.domain == h.dst => {}
                _ => return Err(Reason::SealedToWrongRecipient),
            }
        }

        let next_hop = if h.dst == self.node {
            None
        } else {
            if env.hops == 0 {
                return Err(Reason::HopLimitExceeded);
            }
            let path = match self.find_path(&h.dst, h, Some(bytes.len())) {
                Some(path) => path,
                None if self.find_path(&h.dst, h, None).is_some() => {
                    return Err(Reason::PayloadTooLarge);
                }
                None => return Err(Reason::NoRoute),
            };
            if path.len().saturating_sub(1) > usize::from(env.hops) {
                return Err(Reason::HopLimitExceeded);
            }
            Some(path.get(1).cloned().ok_or(Reason::NoRoute)?)
        };

        state.purge(now);
        if state.seen.contains_key(&h.id) {
            return Err(Reason::Replay);
        }
        if state.seen.len() >= policy.replay_capacity {
            return Err(Reason::Overloaded);
        }
        if !state.take_token(&h.src, src.rate_per_sec, src.burst, now) {
            return Err(Reason::RateLimited);
        }
        state.remember(h.id, h.expires_ms.saturating_add(policy.clock_skew_ms));

        match next_hop {
            None => Ok((Verdict::Deliver, None)),
            Some(next_hop) => {
                let mut onward = env.clone();
                onward.hops -= 1;
                let bytes = onward.encode().map_err(|_| Reason::Malformed)?;
                Ok((Verdict::Forward { next_hop }, Some(bytes)))
            }
        }
    }

    /// Shortest path from this node to `to` over edges and relays that permit
    /// the header's label (and the envelope size, when given). Neighbours are
    /// visited in name order, so every implementation picks the same path.
    fn find_path(&self, to: &str, header: &Header, size: Option<usize>) -> Option<Vec<String>> {
        let start = self.node.as_str();
        let mut previous: BTreeMap<&str, &str> = BTreeMap::new();
        let mut seen: BTreeSet<&str> = BTreeSet::from([start]);
        let mut queue: VecDeque<&str> = VecDeque::from([start]);
        while let Some(current) = queue.pop_front() {
            if current == to {
                let mut path = vec![to.to_owned()];
                let mut at = to;
                while let Some(prev) = previous.get(at) {
                    path.push((*prev).to_owned());
                    at = prev;
                }
                path.reverse();
                return Some(path);
            }
            for route in self.policy.routes_from(current) {
                let next = route.to.as_str();
                if seen.contains(next)
                    || !edge_allows(route, header)
                    || size.is_some_and(|s| s > route.max_bytes)
                {
                    continue;
                }
                if next != to
                    && !self
                        .policy
                        .domain(next)
                        .is_some_and(|d| can_hold(d, &header.label))
                {
                    continue;
                }
                seen.insert(next);
                previous.insert(next, current);
                queue.push_back(next);
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::envelope::{Draft, seal_and_sign};
    use crate::keys::SecretKeys;

    const POLICY: &str = "\
policy version=1 name=test max-lifetime=3600
domain name=ground conf=high integ=high avail=high comp=ops,tt-c
domain name=relay conf=moderate integ=moderate avail=high comp=tt-c
domain name=craft conf=moderate integ=high avail=high comp=tt-c integ-floor=moderate
domain name=lab conf=low integ=moderate avail=low comp=science
route from=ground to=relay bidirectional=yes
route from=relay to=craft bidirectional=yes
route from=lab to=ground
";
    const T0: u64 = 1_767_225_600_000;

    struct Net {
        keys: BTreeMap<&'static str, SecretKeys>,
        ring: Keyring,
    }

    fn net() -> Net {
        let mut keys = BTreeMap::new();
        let mut ring = Keyring::new();
        for d in ["ground", "relay", "craft", "lab"] {
            let k = SecretKeys::generate(d).unwrap();
            ring.add(k.public()).unwrap();
            keys.insert(d, k);
        }
        Net { keys, ring }
    }

    fn router(net: &Net, node: &str) -> Router {
        Router::new(Policy::parse(POLICY).unwrap(), net.ring.clone(), node).unwrap()
    }

    fn send(net: &Net, src: &'static str, dst: &'static str, label: &str, seal: bool) -> Vec<u8> {
        let draft = Draft {
            src,
            dst,
            label: Label::parse(label).unwrap(),
            content_type: "text/plain",
            ttl_ms: 60_000,
            max_hops: 4,
            payload: b"hello",
        };
        let ek = seal.then(|| net.keys[dst].decapsulation.encapsulation_key());
        seal_and_sign(&draft, &net.keys[src].signing, ek, T0)
            .unwrap()
            .encode()
            .unwrap()
    }

    #[test]
    fn multi_hop_delivery_with_audit_chain() {
        let net = net();
        let msg = send(
            &net,
            "ground",
            "craft",
            "conf=moderate integ=high avail=high comp=tt-c",
            true,
        );
        let at_ground = router(&net, "ground").route(&msg, None, T0);
        assert_eq!(
            at_ground.verdict,
            Verdict::Forward {
                next_hop: "relay".into()
            }
        );
        let relay = router(&net, "relay");
        let at_relay = relay.route(
            at_ground.forwarded.as_ref().unwrap(),
            Some("ground"),
            T0 + 5,
        );
        assert_eq!(
            at_relay.verdict,
            Verdict::Forward {
                next_hop: "craft".into()
            }
        );
        let at_craft = router(&net, "craft").route(
            at_relay.forwarded.as_ref().unwrap(),
            Some("relay"),
            T0 + 9,
        );
        assert_eq!(at_craft.verdict, Verdict::Deliver);
        assert_eq!(at_craft.envelope.unwrap().hops, 2);
        // A second copy at the relay is a replay.
        let again = relay.route(
            at_ground.forwarded.as_ref().unwrap(),
            Some("ground"),
            T0 + 6,
        );
        assert_eq!(again.verdict, Verdict::Reject(Reason::Replay));
        let log = format!("{}\n{}\n", at_relay.audit_line, again.audit_line);
        assert_eq!(crate::audit::verify_chain(&log).unwrap().seq(), 2);
    }

    #[test]
    fn label_rules() {
        let net = net();
        let ground = router(&net, "ground");
        let cases = [
            // Bell–LaPadula: craft is cleared to moderate only.
            (
                "ground",
                "craft",
                "conf=high integ=high avail=high comp=tt-c",
                true,
                Reason::ConfidentialityExceedsDestination,
            ),
            // Biba: craft's integrity floor is moderate.
            (
                "ground",
                "craft",
                "conf=low integ=low avail=high comp=tt-c",
                false,
                Reason::IntegrityBelowFloor,
            ),
            // Sealing is mandatory from moderate confidentiality.
            (
                "ground",
                "craft",
                "conf=moderate integ=high avail=high comp=tt-c",
                false,
                Reason::EncryptionRequired,
            ),
            // craft does not hold the ops compartment.
            (
                "ground",
                "craft",
                "conf=low integ=high avail=high comp=ops",
                false,
                Reason::CompartmentNotPermitted,
            ),
            // lab has an outbound route only: nothing can reach it.
            (
                "ground",
                "lab",
                "conf=low integ=moderate avail=low",
                false,
                Reason::NoRoute,
            ),
        ];
        for (src, dst, label, seal, want) in cases {
            let decision = ground.route(&send(&net, src, dst, label, seal), None, T0);
            assert_eq!(decision.verdict, Verdict::Reject(want), "{label}");
        }
    }

    #[test]
    fn authenticity_freshness_and_rate() {
        let net = net();
        let ground = router(&net, "ground");
        let ok = send(
            &net,
            "ground",
            "relay",
            "conf=low integ=moderate avail=high comp=tt-c",
            false,
        );
        // Arriving at a node that is not the source, with no arrival edge.
        assert_eq!(
            router(&net, "relay").route(&ok, None, T0).verdict,
            Verdict::Reject(Reason::UnexpectedArrival)
        );
        assert_eq!(
            ground.route(&ok, None, T0 + 3_600_000).verdict,
            Verdict::Reject(Reason::Expired)
        );
        assert_eq!(
            ground.route(&ok, None, T0 - 600_000).verdict,
            Verdict::Reject(Reason::NotYetValid)
        );
        let mut tampered = Envelope::decode(&ok).unwrap();
        tampered.payload = b"HELLO".to_vec();
        let tampered = tampered.encode().unwrap();
        assert_eq!(
            ground.route(&tampered, None, T0).verdict,
            Verdict::Reject(Reason::BadSignature)
        );
        assert_eq!(
            ground.route(b"\x00", None, T0).verdict,
            Verdict::Reject(Reason::Malformed)
        );
        let mut inflated = Envelope::decode(&ok).unwrap();
        inflated.hops = 9;
        let inflated = inflated.encode().unwrap();
        assert_eq!(
            ground.route(&inflated, None, T0).verdict,
            Verdict::Reject(Reason::HopCountInflated)
        );
    }
}
