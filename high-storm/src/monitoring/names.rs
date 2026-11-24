//! Every metric this node exports, with its kind and help text.

/// Declares a constant per metric name and `describe`, which registers the
/// help text of each metric, in table order.
macro_rules! metrics {
    ($($describe:ident $name:ident = $metric:literal, $help:literal;)*) => {
        $(pub(super) const $name: &str = $metric;)*

        pub(super) fn describe() {
            $(metrics::$describe!($name, $help);)*
        }
    };
}

metrics! {
    describe_gauge BUILD_INFO = "high_storm_build_info",
        "Always 1; the labels identify the running high-storm build.";
    describe_gauge MONITORING_TASK_LAST_RUN = "high_storm_monitoring_task_last_run_timestamp_seconds",
        "Unix time each background metrics task last finished a pass, or started if it has not finished one; stale means its gauges are too.";
    describe_counter MONITORING_TASK_ERRORS = "high_storm_monitoring_task_errors_total",
        "Reads a background metrics task failed, leaving the gauges they feed at their last values.";
    describe_counter METRICS_CONNECTIONS_REJECTED = "high_storm_metrics_connections_rejected_total",
        "Connections to this metrics endpoint closed on accept because every slot was taken.";
    describe_gauge LOOP_LAST_TICK = "high_storm_loop_last_tick_timestamp_seconds",
        "Unix time at which each main loop task last started.";
    describe_gauge IS_MEMBER = "high_storm_is_member",
        "1 while this node is in the network's member table.";
    describe_gauge IS_COORDINATOR = "high_storm_is_coordinator",
        "1 if this node coordinates user requests.";
    describe_gauge IS_LEADER = "high_storm_is_leader",
        "1 if this node leads at the current block height.";
    describe_gauge BLOCK_HEIGHT = "high_storm_block_height",
        "Height of the last Liquid block this node indexed.";
    describe_gauge MEMBERS_TOTAL = "high_storm_members_total",
        "Members in the network, this node included.";
    describe_gauge SIGNING_THRESHOLD = "high_storm_signing_threshold",
        "Signers a Storm Tree branch needs: two-thirds of the members, rounded up.";
    describe_gauge CONNECTED_MEMBERS = "high_storm_connected_members",
        "Members signing can use now: this node plus the active members it is connected to.";
    describe_gauge COORDINATOR_CONNECTED = "high_storm_coordinator_connected",
        "1 if this node is the coordinator or is connected to it.";
    describe_gauge PEER_CONNECTED = "storm_peer_connected",
        "1 while the peer is active and its connection is open.";
    describe_gauge PEER_LAST_SEEN = "storm_peer_last_seen_timestamp_seconds",
        "Unix time of the last message received from the peer.";
    describe_gauge DB_UP = "high_storm_db_up",
        "1 if a trivial query completed within 2s, which also needs a free pool connection.";
    describe_histogram DB_PING_DURATION = "high_storm_db_ping_duration_seconds",
        "Time taken by the database probe that succeeded.";
    describe_gauge DB_POOL_CONNECTIONS = "high_storm_db_pool_connections",
        "Database pool connections, by state.";
    describe_gauge DB_POOL_MAX_CONNECTIONS = "high_storm_db_pool_max_connections",
        "Connections the database pool may open; the probe fails when all are used.";
    describe_gauge ELEMENTS_RPC_UP = "high_storm_elements_rpc_up",
        "1 if the last probe of this node's Elements RPC succeeded.";
    describe_gauge ELEMENTS_TIP_HEIGHT = "high_storm_elements_tip_height",
        "Height of Elements' best block, as last seen.";
    describe_gauge ELEMENTS_TIP_TIMESTAMP = "high_storm_elements_tip_timestamp_seconds",
        "Unix time of Elements' best block, as last seen.";
    describe_gauge ELEMENTS_PEERS = "high_storm_elements_peers",
        "Peers Elements is connected to, as last seen.";
    describe_gauge ELEMENTS_INITIAL_BLOCK_DOWNLOAD = "high_storm_elements_initial_block_download",
        "1 while Elements is in initial block download.";
    describe_counter ELEMENTS_RPC_ERRORS = "high_storm_elements_rpc_errors_total",
        "Failed Elements RPC calls, by method and reason: transport when Elements did not answer, rpc when it answered with an error.";
    describe_histogram ELEMENTS_RPC_DURATION = "high_storm_elements_rpc_duration_seconds",
        "Time an Elements RPC call took, by method.";
    describe_counter TX_BROADCASTS = "high_storm_tx_broadcast_total",
        "Transactions sent to Elements, by kind and outcome: accepted, inputs_spent (also a confirmed one resent), rejected or failed.";
    describe_counter CHAIN_REORGS = "high_storm_chain_reorgs_total",
        "Chain reorganizations the indexer found under its journal or cursors.";
    describe_gauge CHAIN_RECOVERING = "high_storm_chain_recovering",
        "1 while the indexer rebuilds chain-derived state.";
    describe_gauge CHAIN_SAFETY_HALT = "high_storm_chain_safety_halt",
        "1 while indexing is halted for safety; an operator must act.";
    describe_gauge SPENDING_PAUSED = "high_storm_spending_paused",
        "1 while spending is paused for a member migration.";
    describe_gauge STORM_EYE_UTXOS = "high_storm_storm_eye_utxos",
        "Storm Eye UTXOs available to sign with, counted after each new block.";
    describe_gauge STORM_EYE_RESCUE_BLOCKS_REMAINING = "high_storm_storm_eye_rescue_blocks_remaining",
        "Blocks until anyone may take the Storm Eye UTXOs; negative once passed.";
    describe_counter STORM_EYE_RENEWALS = "high_storm_storm_eye_renewals_total",
        "Storm Eye timelock renewals, by outcome.";
    describe_gauge PRICE_FEED_AVAILABLE = "high_storm_price_feed_available",
        "1 while the feed has a valid price; only feeds some source can price are reported.";
    describe_gauge PRICE_FEED_RECEIVED = "high_storm_price_feed_received_timestamp_seconds",
        "Unix time the feed's current price was received.";
    describe_gauge PRICE_FEED_VALID_UNTIL = "high_storm_price_feed_valid_until_timestamp_seconds",
        "Unix time until which the feed's current price is valid.";
    describe_gauge PRICE_FEED_ACTIVE_SOURCES = "high_storm_price_feed_active_sources",
        "Sources of a Direct feed that are neither dropped nor frozen.";
    describe_gauge PRICE_SOURCE_STATE = "high_storm_price_source_state",
        "1 for the state a feed's source is in: active, dropped or frozen.";
    describe_gauge PRICE_SOURCE_LAST_OBSERVED = "high_storm_price_source_last_observed_timestamp_seconds",
        "Unix time the source itself stamped its latest kept observation.";
    describe_counter PRICE_POLLS = "high_storm_price_polls_total",
        "Polls of a feed's source, by outcome: observed, unchanged, failed or skipped.";
    describe_counter PRICE_POLL_FAILURES = "high_storm_price_poll_failures_total",
        "Failed polls of a source, by reason.";
    describe_histogram PRICE_POLL_DURATION = "high_storm_price_poll_duration_seconds",
        "Time a source took to answer a poll, failed polls included.";
    describe_gauge PRICE_CHANGE = "high_storm_price_change_bps",
        "Change between a source's last two observations of a feed, in basis points.";
    describe_counter PRICE_ATTESTATIONS_REJECTED = "high_storm_price_attestations_rejected_total",
        "Price attestation messages from a peer that this node refused, by reason.";
    describe_gauge PRICE_PEER_ATTESTATION = "high_storm_price_peer_attestation_timestamp_seconds",
        "Unix time a peer's latest stored price for the feed was received by that peer.";
    describe_gauge PRICE_PEER_DEVIATION = "high_storm_price_peer_deviation_bps",
        "How far a peer's still-valid price is from this node's own, in basis points of its own; NaN while either is missing.";
    describe_gauge API_CONNECTIONS_ACTIVE = "high_storm_api_connections_active",
        "External API connections open; the listener holds 256, and 16 per client IP.";
    describe_counter API_CONNECTIONS_REJECTED = "high_storm_api_connections_rejected_total",
        "External API connections closed on accept, by limit: global or per_client.";
    describe_counter API_REQUESTS_REJECTED = "high_storm_api_requests_rejected_total",
        "External API requests refused by a request limit, by reason.";
    describe_counter API_REQUESTS = "high_storm_api_requests_total",
        "External API requests answered, by route template, method and status.";
    describe_histogram API_REQUEST_DURATION = "high_storm_api_request_duration_seconds",
        "Time taken to answer an external API request, by route template.";
    describe_counter OPERATOR_AUTH_FAILURES = "high_storm_operator_auth_failures_total",
        "Failed operator authentications, by reason.";
    describe_counter USER_REQUESTS_REJECTED = "high_storm_user_requests_rejected_total",
        "User requests the API refused to register, by reason.";
    describe_counter IPC_REJECTED = "high_storm_ipc_rejected_total",
        "Operator IPC connections refused, by reason: no_credentials or uid.";
    describe_counter OPERATOR_CHANGES = "high_storm_operator_changes_total",
        "Operators added or removed over IPC, by action.";
    describe_gauge OPERATORS = "high_storm_operators",
        "Operators allowed to use the operator API.";
    describe_counter NODE_MESSAGES_REJECTED = "high_storm_node_messages_rejected_total",
        "Node messages from a peer that this node rejected, by kind and reason.";
    describe_counter UNAUTHORIZED_MESSAGES = "high_storm_unauthorized_messages_total",
        "Messages from a peer acting outside its role, such as a non-coordinator starting user-request signing.";
    describe_counter SIGNING_ATTEMPTS = "high_storm_signing_attempts_total",
        "Signings this node requested, by message kind and outcome: ok or the reason it failed.";
    describe_histogram SIGNING_DURATION = "high_storm_signing_duration_seconds",
        "Time a signing this node requested took to succeed.";
    describe_counter SIGNING_BRANCH_FAILURES = "high_storm_signing_branch_failures_total",
        "Storm Tree branches that failed within a signing, by reason: timeout or error.";
    describe_counter SIGNING_MISSING_CONTRIBUTIONS = "high_storm_signing_missing_contributions_total",
        "Signers that never sent their nonces or partial signatures for a signing this node requested.";
    describe_counter SIGNING_INVALID_PARTIAL_SIGNATURES = "high_storm_signing_invalid_partial_signatures_total",
        "Partial signatures from a signer that failed to parse or verify.";
    describe_counter SIGNING_AGGREGATE_INVALID = "high_storm_signing_aggregate_invalid_total",
        "Aggregated signatures that failed verification although every partial signature verified.";
    describe_gauge SIGNING_SESSIONS_ACTIVE = "high_storm_signing_sessions_active",
        "Signing sessions this node holds, its own and its peers'.";
    describe_gauge MONITORED_UTXOS = "high_storm_monitored_utxos",
        "Issued Ticks and Verifiers this node tracks, by state.";
    describe_gauge EXPIRED_UTXO_OLDEST_AGE = "high_storm_expired_utxo_oldest_age_blocks",
        "Blocks since the oldest unburned Tick or Verifier expired; 0 when none is waiting.";
    describe_counter BURN_ROUNDS = "high_storm_burn_rounds_total",
        "Burn rounds this node led that had something to burn, by outcome.";
    describe_counter BURNING_REVERTED = "high_storm_burning_reverted_total",
        "Burns returned to the queue because their transaction was not confirmed in time.";
    describe_gauge USER_REQUESTS = "high_storm_user_requests",
        "User requests in this node's database, by status.";
    describe_gauge USER_REQUEST_OLDEST_PENDING_AGE = "high_storm_user_request_oldest_pending_age_blocks",
        "Blocks since the oldest user request not yet in a block was submitted; 0 when none.";
    describe_counter USER_REQUESTS_FAILED = "high_storm_user_requests_failed_total",
        "User requests marked failed, by reason.";
    describe_histogram ISSUANCE_TX_WEIGHT = "high_storm_issuance_tx_weight",
        "Weight of each issuance transaction this node broadcast, in weight units.";
    describe_gauge TREASURY_BALANCE = "high_storm_treasury_balance_sats",
        "Sats held in Treasury UTXOs, as this node indexed them.";
    describe_gauge DROPLETS_BALANCE = "high_storm_droplets_balance_sats",
        "Droplets credited to this node, in sats.";
    describe_counter ISSUANCE_ROUNDS = "high_storm_issuance_rounds_total",
        "Issuance rounds this node coordinated that had requests to issue, by outcome.";
    describe_counter SIGNING_REFUSED = "high_storm_signing_refused_total",
        "Signing requests this node refused: price_* when its own price disagrees, invalid when the proposal is wrong, other for a local failure.";
    describe_counter VOTING_REQUESTS_CREATED = "high_storm_voting_requests_created_total",
        "Governance votes this node stored for the first time, by kind and proposer.";
    describe_counter VOTING_APPROVALS = "high_storm_voting_approvals_total",
        "Approvals of governance votes this node stored for the first time, by vote kind.";
    describe_gauge VOTING_REQUESTS_OPEN = "high_storm_voting_requests_open",
        "Governance votes not yet executed and confirmed, by kind.";
    describe_counter VOTING_EXECUTIONS = "high_storm_voting_executions_total",
        "Vote executions this node ran or confirmed, by outcome.";
    describe_gauge MEMBER_MIGRATION_IN_PROGRESS = "high_storm_member_migration_in_progress",
        "1 while an approved member update is being executed.";
    describe_gauge MEMBER_MIGRATION_READY = "high_storm_member_migration_ready",
        "1 once every member of the new network is connected, so the member update can be executed.";
    describe_counter DROPLETS_EXCHANGES = "high_storm_droplets_exchanges_total",
        "Queued Droplets exchanges this node ran as leader, by outcome.";
}
