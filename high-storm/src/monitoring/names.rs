pub(super) const METRICS_CONNECTIONS_REJECTED: &str =
    "high_storm_metrics_connections_rejected_total";
pub(super) const BUILD_INFO: &str = "high_storm_build_info";

pub(super) const LOOP_LAST_TICK: &str = "high_storm_loop_last_tick_timestamp_seconds";
pub(super) const IS_MEMBER: &str = "high_storm_is_member";
pub(super) const IS_COORDINATOR: &str = "high_storm_is_coordinator";
pub(super) const IS_LEADER: &str = "high_storm_is_leader";
pub(super) const BLOCK_HEIGHT: &str = "high_storm_block_height";

pub(super) const MEMBERS_TOTAL: &str = "high_storm_members_total";
pub(super) const SIGNING_THRESHOLD: &str = "high_storm_signing_threshold";
pub(super) const CONNECTED_MEMBERS: &str = "high_storm_connected_members";
pub(super) const COORDINATOR_CONNECTED: &str = "high_storm_coordinator_connected";
pub(super) const PEER_CONNECTED: &str = "storm_peer_connected";
pub(super) const PEER_LAST_SEEN: &str = "storm_peer_last_seen_timestamp_seconds";

pub(super) const DB_UP: &str = "high_storm_db_up";
pub(super) const DB_PING_DURATION: &str = "high_storm_db_ping_duration_seconds";
pub(super) const DB_POOL_MAX_CONNECTIONS: &str = "high_storm_db_pool_max_connections";
pub(super) const DB_POOL_CONNECTIONS: &str = "high_storm_db_pool_connections";

pub(super) const ELEMENTS_RPC_UP: &str = "high_storm_elements_rpc_up";
pub(super) const ELEMENTS_TIP_HEIGHT: &str = "high_storm_elements_tip_height";
pub(super) const ELEMENTS_TIP_TIMESTAMP: &str = "high_storm_elements_tip_timestamp_seconds";
pub(super) const ELEMENTS_PEERS: &str = "high_storm_elements_peers";
pub(super) const ELEMENTS_RPC_ERRORS: &str = "high_storm_elements_rpc_errors_total";
pub(super) const ELEMENTS_RPC_DURATION: &str = "high_storm_elements_rpc_duration_seconds";
pub(super) const TX_BROADCASTS: &str = "high_storm_tx_broadcast_total";
pub(super) const ELEMENTS_INITIAL_BLOCK_DOWNLOAD: &str =
    "high_storm_elements_initial_block_download";

pub(super) const CHAIN_REORGS: &str = "high_storm_chain_reorgs_total";
pub(super) const CHAIN_RECOVERING: &str = "high_storm_chain_recovering";
pub(super) const CHAIN_SAFETY_HALT: &str = "high_storm_chain_safety_halt";
pub(super) const SPENDING_PAUSED: &str = "high_storm_spending_paused";

pub(super) const STORM_EYE_UTXOS: &str = "high_storm_storm_eye_utxos";
pub(super) const STORM_EYE_RESCUE_BLOCKS_REMAINING: &str =
    "high_storm_storm_eye_rescue_blocks_remaining";
pub(super) const STORM_EYE_RENEWALS: &str = "high_storm_storm_eye_renewals_total";

pub(super) const PRICE_FEED_AVAILABLE: &str = "high_storm_price_feed_available";
pub(super) const PRICE_FEED_RECEIVED: &str = "high_storm_price_feed_received_timestamp_seconds";
pub(super) const PRICE_FEED_VALID_UNTIL: &str =
    "high_storm_price_feed_valid_until_timestamp_seconds";
pub(super) const PRICE_FEED_ACTIVE_SOURCES: &str = "high_storm_price_feed_active_sources";
pub(super) const PRICE_SOURCE_STATE: &str = "high_storm_price_source_state";
pub(super) const PRICE_SOURCE_LAST_OBSERVED: &str =
    "high_storm_price_source_last_observed_timestamp_seconds";
pub(super) const PRICE_POLLS: &str = "high_storm_price_polls_total";
pub(super) const PRICE_POLL_FAILURES: &str = "high_storm_price_poll_failures_total";
pub(super) const PRICE_POLL_DURATION: &str = "high_storm_price_poll_duration_seconds";
pub(super) const PRICE_CHANGE: &str = "high_storm_price_change_bps";
pub(super) const PRICE_ATTESTATIONS_REJECTED: &str = "high_storm_price_attestations_rejected_total";
pub(super) const PRICE_PEER_ATTESTATION: &str =
    "high_storm_price_peer_attestation_timestamp_seconds";
pub(super) const PRICE_PEER_DEVIATION: &str = "high_storm_price_peer_deviation_bps";

pub(super) const API_CONNECTIONS_ACTIVE: &str = "high_storm_api_connections_active";
pub(super) const API_CONNECTIONS_REJECTED: &str = "high_storm_api_connections_rejected_total";
pub(super) const API_REQUESTS_REJECTED: &str = "high_storm_api_requests_rejected_total";
pub(super) const API_REQUESTS: &str = "high_storm_api_requests_total";
pub(super) const API_REQUEST_DURATION: &str = "high_storm_api_request_duration_seconds";
pub(super) const OPERATOR_AUTH_FAILURES: &str = "high_storm_operator_auth_failures_total";
pub(super) const USER_REQUESTS_REJECTED: &str = "high_storm_user_requests_rejected_total";
pub(super) const IPC_REJECTED: &str = "high_storm_ipc_rejected_total";
pub(super) const OPERATOR_CHANGES: &str = "high_storm_operator_changes_total";
pub(super) const OPERATORS: &str = "high_storm_operators";

pub(super) const NODE_MESSAGES_REJECTED: &str = "high_storm_node_messages_rejected_total";
pub(super) const UNAUTHORIZED_MESSAGES: &str = "high_storm_unauthorized_messages_total";
pub(super) const SIGNING_REFUSED: &str = "high_storm_signing_refused_total";

pub(super) const SIGNING_ATTEMPTS: &str = "high_storm_signing_attempts_total";
pub(super) const SIGNING_DURATION: &str = "high_storm_signing_duration_seconds";
pub(super) const SIGNING_BRANCH_FAILURES: &str = "high_storm_signing_branch_failures_total";
pub(super) const SIGNING_MISSING_CONTRIBUTIONS: &str =
    "high_storm_signing_missing_contributions_total";
pub(super) const SIGNING_INVALID_PARTIAL_SIGNATURES: &str =
    "high_storm_signing_invalid_partial_signatures_total";
pub(super) const SIGNING_AGGREGATE_INVALID: &str = "high_storm_signing_aggregate_invalid_total";
pub(super) const SIGNING_SESSIONS_ACTIVE: &str = "high_storm_signing_sessions_active";

pub(super) const MONITORED_UTXOS: &str = "high_storm_monitored_utxos";
pub(super) const EXPIRED_UTXO_OLDEST_AGE: &str = "high_storm_expired_utxo_oldest_age_blocks";
pub(super) const BURN_ROUNDS: &str = "high_storm_burn_rounds_total";
pub(super) const BURNING_REVERTED: &str = "high_storm_burning_reverted_total";
pub(super) const USER_REQUESTS: &str = "high_storm_user_requests";
pub(super) const USER_REQUEST_OLDEST_PENDING_AGE: &str =
    "high_storm_user_request_oldest_pending_age_blocks";
pub(super) const USER_REQUESTS_FAILED: &str = "high_storm_user_requests_failed_total";
pub(super) const ISSUANCE_ROUNDS: &str = "high_storm_issuance_rounds_total";
pub(super) const ISSUANCE_TX_WEIGHT: &str = "high_storm_issuance_tx_weight";
pub(super) const TREASURY_BALANCE: &str = "high_storm_treasury_balance_sats";
pub(super) const DROPLETS_BALANCE: &str = "high_storm_droplets_balance_sats";

pub(super) const VOTING_REQUESTS_CREATED: &str = "high_storm_voting_requests_created_total";
pub(super) const VOTING_APPROVALS: &str = "high_storm_voting_approvals_total";
pub(super) const VOTING_REQUESTS_OPEN: &str = "high_storm_voting_requests_open";
pub(super) const VOTING_EXECUTIONS: &str = "high_storm_voting_executions_total";
pub(super) const MEMBER_MIGRATION_IN_PROGRESS: &str = "high_storm_member_migration_in_progress";
pub(super) const MEMBER_MIGRATION_READY: &str = "high_storm_member_migration_ready";
pub(super) const DROPLETS_EXCHANGES: &str = "high_storm_droplets_exchanges_total";
