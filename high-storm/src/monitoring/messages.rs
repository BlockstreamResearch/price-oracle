use metrics::counter;

use super::names;

/// A peer's node message this node rejected, with labels already chosen.
pub(crate) struct RejectedMessage {
    pub(crate) peer: [u8; 33],
    pub(crate) kind: &'static str,
    pub(crate) reason: &'static str,
    /// The sender acted outside its role, such as a non-coordinator.
    pub(crate) unauthorized: bool,
    /// Set when a signing request was refused, with why.
    pub(crate) refusal: Option<&'static str>,
}

pub(crate) fn record_rejected_message(rejected: &RejectedMessage) {
    let peer = hex::encode(rejected.peer);
    counter!(
        names::NODE_MESSAGES_REJECTED,
        "peer" => peer.clone(),
        "kind" => rejected.kind,
        "reason" => rejected.reason,
    )
    .increment(1);
    if rejected.unauthorized {
        counter!(
            names::UNAUTHORIZED_MESSAGES,
            "peer" => peer.clone(),
            "kind" => rejected.kind,
        )
        .increment(1);
    }
    if let Some(reason) = rejected.refusal {
        counter!(
            names::SIGNING_REFUSED,
            "peer" => peer,
            "kind" => rejected.kind,
            "reason" => reason,
        )
        .increment(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::monitoring::builder;

    #[test]
    fn counts_a_refused_signing_request_under_every_series() {
        let recorder = builder().unwrap().build_recorder();
        let peer = hex::encode([2; 33]);

        metrics::with_local_recorder(&recorder, || {
            record_rejected_message(&RejectedMessage {
                peer: [2; 33],
                kind: "execute_user_requests",
                reason: "user_request",
                unauthorized: false,
                refusal: Some("price_deviation_exceeded"),
            });
            record_rejected_message(&RejectedMessage {
                peer: [2; 33],
                kind: "renew_storm_utxos",
                reason: "unauthorized",
                unauthorized: true,
                refusal: None,
            });
        });

        let rendered = recorder.handle().render();
        for line in [
            format!(
                r#"high_storm_node_messages_rejected_total{{peer="{peer}",kind="execute_user_requests",reason="user_request"}} 1"#
            ),
            format!(
                r#"high_storm_signing_refused_total{{peer="{peer}",kind="execute_user_requests",reason="price_deviation_exceeded"}} 1"#
            ),
            format!(
                r#"high_storm_unauthorized_messages_total{{peer="{peer}",kind="renew_storm_utxos"}} 1"#
            ),
        ] {
            assert!(rendered.contains(&line), "missing {line:?} in:\n{rendered}");
        }
        // A refusal is not an authorization failure.
        assert!(!rendered.contains(&format!(
            r#"high_storm_unauthorized_messages_total{{peer="{peer}",kind="execute_user_requests"}}"#
        )));
    }
}
