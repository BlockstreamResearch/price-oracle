# Alert runbook

One entry per item of the failure catalog; every rule in `alerts.yml` links to
its entry through `runbook_url`. **Check** is where to look first, **Act** what
usually resolves it. Most checks use the node log, the metrics at
`/metrics`, and the operator API (`/operators/state`, `/operators/state/peers`,
`/operators/storm-eyes`), which the operator platform shows.

Severity: `page` needs someone now (the network or funds are at risk), `warn`
within working hours, `info` is for the dashboard.

## 1. The node itself

### <a id="11"></a>1.1 Node down, or no node scraped

- **Check:** the process and its container; the last lines of its log; whether
  `service.metrics.address` is set and the node is a scrape target.
- **Act:** restart it. A node that exits right after starting is usually a
  configuration or database error, printed in the log.

### <a id="12"></a>1.2 Restart loop

- **Check:** the log of each start for the error it exits on.
- **Act:** fix that cause. A node removed by a vote exits on purpose (see 1.4).

### <a id="13"></a>1.3 Main loop stuck

- **Check:** the log for the last loop activity; whether a signing round or an
  Elements or database call hangs.
- **Act:** restart the node after saving its log. Report the hang: the loop
  should never block for minutes.

### <a id="14"></a>1.4 No longer a member

- **Check:** the executed votes in the operator API for an `update_network_members`
  vote that removed this key.
- **Act:** expected after such a vote; otherwise treat as 3.10.

### <a id="16"></a>1.6 Database down, slow or out of connections

- **Check:** PostgreSQL itself (`pg_isready`), disk space on its host, and
  `high_storm_db_pool_connections` against `high_storm_db_pool_max_connections`.
- **Act:** bring PostgreSQL back. A pool that stays full points at slow queries
  or a too small `service.db.max_connections`.

### <a id="17"></a>1.7 File descriptors or disk running out

- **Check:** `process_open_fds` against `process_max_fds`; free space on the
  database and Elements volumes (node_exporter).
- **Act:** raise the file limit or free disk space before the node or Elements
  fails on writes.

## 2. Peers and quorum

### <a id="21"></a>2.1 Peer offline

- **Check:** `/operators/state/peers`; whether the peer's operator knows; its
  `storm_peer_last_seen_timestamp_seconds`.
- **Act:** contact the peer's operator. One offline peer of three leaves the
  network exactly at quorum (2.3).

### <a id="22"></a>2.2 Quorum lost

- **Check:** which members are unreachable (2.1 alerts); whether this node, not
  the others, is the one cut off (its network, firewall, P2P port).
- **Act:** restore connectivity to enough members. Until then nothing is signed:
  no issuance, no burns, no Storm Eye renewal.

### <a id="23"></a>2.3 No redundancy

- **Check:** the one member that is missing.
- **Act:** bring it back; one more failure stops signing.

### <a id="24"></a>2.4 Coordinator unreachable

- **Check:** whether the coordinator's node is up (1.1) and reachable from the
  other members on its P2P port.
- **Act:** restore the coordinator. The user API depends on it network-wide.

### <a id="25"></a>2.5 Flapping connection

- **Check:** `storm_peer_disconnections_total` reasons for that peer; the network
  path between the two nodes.
- **Act:** fix the unstable link. A `replay` or `rate_limit` reason is 3.1 or 3.2.

### <a id="26"></a>2.6 Backpressure or timeouts

- **Check:** which stage times out; whether the peer is down (then 2.1 explains
  it) or slow.
- **Act:** a slow peer is its operator's to fix; a write timeout to many peers
  points at this node's own network.

### <a id="27"></a>2.7 Protocol version mismatch

- **Check:** `storm_peer_protocol_version` per peer.
- **Act:** finish the rollout so every member runs the same release.

### <a id="28"></a>2.8 DNS resolution failing

- **Check:** the peer's configured address and the resolver on this host.
- **Act:** fix the DNS record or `service.peer_addresses`.

## 3. A member misbehaving

These carry the peer's key, which is the evidence for a removal vote. Keep the
alert and the node log before acting.

### <a id="31"></a>3.1 Peer replays messages

- **Check:** how often, and whether it began with a restart or reconnection of
  that peer; honest nodes should never repeat a message.
- **Act:** report it to the peer's operator; if it persists, raise it with the
  other operators.

### <a id="32"></a>3.2 Peer floods

- **Check:** the rate and the peer's release.
- **Act:** as 3.1. The node already drops the excess.

### <a id="33"></a>3.3 Malformed or rejected messages

- **Check:** the `reason` and `kind` labels and the log lines for that peer.
- **Act:** a release mismatch (2.7) explains decode errors; anything else goes
  to the peer's operator.

### <a id="34"></a>3.4 Message outside the sender's role

- **Check:** the `kind`; who the coordinator and leader were at the time.
- **Act:** page the other operators: a member that starts signing outside its
  role may be compromised.

### <a id="35"></a>3.5 Signing refused

- **Check:** the `reason`. `price_*` means this node's price disagrees (see 5.x
  on this node first); `invalid` means the proposal itself was wrong.
- **Act:** if this node's prices are healthy, report the proposer.

### <a id="36"></a>3.6 Bad partial or aggregate signature

- **Check:** the peer and the `kind`.
- **Act:** page the other operators; a member producing bad signatures may be
  compromised or broken.

### <a id="37"></a>3.7 Signer withholding contributions

- **Check:** whether the peer is up (2.1) and the `stage`.
- **Act:** report the peer; repeated withholding is grounds for a removal vote.

### <a id="38"></a>3.8 Invalid price attestation

- **Check:** the `reason`; `implausible_timestamp` across several peers is this
  node's clock (6.1).
- **Act:** report the peer otherwise.

### <a id="39"></a>3.9 Peer price far from ours

- **Check:** this node's own sources (5.x) and the other peers' deviation.
- **Act:** if only one peer deviates, report it; if all do, suspect this node.

### <a id="310"></a>3.10 Governance vote proposed

- **Check:** the vote in the operator API: its kind, proposer and payload.
- **Act:** confirm it with the proposing operator before approving. Never
  approve a member change you did not agree to off-band.

### <a id="311"></a>3.11 Rejected handshakes

- **Check:** the `reason`; `unauthorized` means keys that are not members.
- **Act:** scanning is noise unless it is heavy; restrict the P2P port to
  members' addresses if possible.

### <a id="312"></a>3.12 Too many signing sessions

- **Check:** memory use and which peers start sessions.
- **Act:** report a peer that opens sessions it does not complete.

## 4. Abuse of the API, P2P port and IPC

### <a id="41"></a>4.1 Connection flood on the API

- **Check:** connection sources at the reverse proxy or firewall.
- **Act:** block abusive addresses upstream; the node already sheds them.

### <a id="42"></a>4.2 Request flood

- **Check:** which routes are hit (`high_storm_api_requests_total`).
- **Act:** rate-limit upstream.

### <a id="43"></a>4.3 API errors or slow

- **Check:** the routes with 5xx answers and the log; Elements and database
  health (7.1, 1.6), which most routes depend on.
- **Act:** fix the dependency that fails.

### <a id="44"></a>4.4 Operator authentication failures

- **Check:** the `reason`; `unknown_operator` is a key that is not registered.
- **Act:** if no operator expects failures, treat it as an attack on the
  operator login and restrict access to the API.

### <a id="45"></a>4.5 User request spam

- **Check:** the `reason` breakdown.
- **Act:** informational; rate-limit upstream if it grows.

### <a id="46"></a>4.6 P2P inbound slots exhausted

- **Check:** connections on the P2P port and their sources.
- **Act:** block flooding addresses; members cannot connect while slots are full.

### <a id="47"></a>4.7 Refused IPC connection

- **Check:** which local user tried to use the operator socket.
- **Act:** investigate the host; only the node's own user and root may use it.

### <a id="48"></a>4.8 Operator set changed

- **Check:** who ran `storm-operator` on the host, and `high_storm_operators`.
- **Act:** expected after an intended change; otherwise remove the operator and
  investigate the host.

## 5. Prices

### <a id="51"></a>5.1 Price source failing

- **Check:** the `reason`: `rate_limited` and `unauthorized` mean the API key or
  plan; `request_failure` the network; `clock_skew` this host's clock (6.2).
- **Act:** fix the key, plan or network.

### <a id="52"></a>5.2 Source dropped

- **Check:** 5.1 for why it failed.
- **Act:** the source is retried automatically once the cause is gone.

### <a id="53"></a>5.3 Feed has no valid price

- **Check:** the feed's sources (5.1, 5.2) and, for a Cross pair, its legs.
- **Act:** restore a source. Requests that need the feed fail after 10 blocks.

### <a id="54"></a>5.4 Source stuck

- **Check:** whether the source still updates the asset at all.
- **Act:** usually resolves at the source; freeze it if it serves stale data.

### <a id="55"></a>5.5 Too few sources

- **Check:** 5.2 for the dropped ones.
- **Act:** with no active source, as 5.3. One source is the known single point
  of failure until a second source exists.

### <a id="56"></a>5.6 Price jump

- **Check:** the market; another source or an exchange for the same pair.
- **Act:** freeze the source if the jump is not real.

### <a id="57"></a>5.7 Peer stopped attesting

- **Check:** whether the peer is up (2.1) and its own price sources.
- **Act:** contact the peer's operator.

## 6. Clock

### <a id="61"></a>6.1 Clock drift

- **Check:** this host's time against a reference (`chronyc tracking` or
  `timedatectl`).
- **Act:** fix time synchronization; prices tolerate only 5 seconds of skew.

### <a id="62"></a>6.2 NTP not synchronized

- **Check:** the time service on the host.
- **Act:** as 6.1.

## 7. Elements and the indexer

### <a id="71"></a>7.1 Elements RPC down or failing

- **Check:** the Elements process, its RPC credentials and port.
- **Act:** restart Elements; the node resumes on its own.

### <a id="72"></a>7.2 Elements stale, without peers, or still syncing

- **Check:** `elements-cli getblockchaininfo` and `getconnectioncount`.
- **Act:** restore its network; a node in initial block download needs time.

### <a id="73"></a>7.3 Indexer behind

- **Check:** the node log for indexing errors; database health (1.6).
- **Act:** fix the error it reports; a short lag after a restart is normal.

### <a id="74"></a>7.4 Reorg, or recovery taking long

- **Check:** the log for the reorg depth and recovery progress.
- **Act:** a short reorg needs nothing; a recovery over 10 minutes needs a look
  at the log.

### <a id="75"></a>7.5 Safety halt

- **Check:** the log line that halted indexing.
- **Act:** an operator must decide before indexing resumes; do not delete
  chain state without understanding the halt.

### <a id="76"></a>7.6 Spending paused too long

- **Check:** the member migration (8.8) that paused it.
- **Act:** finish or resolve the migration.

### <a id="77"></a>7.7 Broadcast rejected or failed

- **Check:** the `kind` and the node log for Elements' answer.
- **Act:** `failed` is 7.1. `rejected` needs the reason (fee, policy); raise the
  relevant fee setting if it is a fee.

## 8. Funds and the Storm Eye

### <a id="81"></a>8.1 Storm Eye UTXOs missing or low

- **Check:** `/operators/storm-eyes`.
- **Act:** with none, nothing can be signed; split or replace them through a vote.

### <a id="82"></a>8.2 Storm Eye timelock expiring

- **Check:** `high_storm_storm_eye_rescue_blocks_remaining` and renewal failures.
- **Act:** get the renewal through before the rescue height: past it, anyone can
  take the Storm Eye UTXOs. Quorum (2.2) is required.

### <a id="83"></a>8.3 Expired Ticks and Verifiers not burned

- **Check:** burn rounds and their failures (8.4, 8.6); quorum (2.2).
- **Act:** restore whatever stops burns; stale prices stay spendable meanwhile.

### <a id="84"></a>8.4 Burn not confirmed

- **Check:** the burn transaction in Elements and its fee.
- **Act:** the burn is retried automatically; repeated reverts point at fees or
  a stuck mempool.

### <a id="85"></a>8.5 User requests stuck or failing

- **Check:** the `reason` of failures and the issuance rounds.
- **Act:** `over_weight` and `unpriced_feed` are the requester's; anything stuck
  points at quorum or prices.

### <a id="86"></a>8.6 Signing failing

- **Check:** the `outcome` labels and missing contributions (3.7).
- **Act:** usually quorum or a withholding peer.

### <a id="87"></a>8.7 Droplets exchange failed

- **Check:** the exchange in the operator API and the node log.
- **Act:** informational; queue it again once the cause is fixed.

### <a id="88"></a>8.8 Vote execution failing or member migration stuck

- **Check:** which target members have not connected yet.
- **Act:** have the new members' operators bring their nodes up.

## Monitoring itself

### <a id="monitoring"></a>Monitoring

- **Watchdog** fires all the time; the paging service should alert when it stops
  arriving, which means Prometheus or Alertmanager is down.
- **A monitoring task missing, stale or failing** means the gauges it publishes
  are frozen and the alerts above that read them cannot fire. Missing means the
  node never started its tasks; stale means one stopped, or never finished a
  pass. Check the node log for the task; restart the node if it does not
  recover.
- **Metrics connections refused** means something holds the metrics endpoint's
  few connections; find the client and restrict who can reach the port.
