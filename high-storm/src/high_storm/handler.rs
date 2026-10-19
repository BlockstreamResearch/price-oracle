use storm::{CustomMsg, StormContext};

use super::{
    assets::AssetError,
    burning::BurningError,
    droplets::DropletsError,
    leader,
    message::{
        BurnExpiredUtxos, ChainTip, ExecuteVotingRequest, ExpiredUtxosBurned, NodeMessage,
        NodeMessageKind, ProtocolSettings, RenewStormUtxos,
    },
    prices::price_hash,
    signing::SigningError,
    state::NetworkState,
    voting::{VotingError, VotingStatus},
};

#[derive(Debug, thiserror::Error)]
pub(crate) enum HandlerError {
    #[error("chain state is being rebuilt after a reorganization")]
    Recovering,
    #[error("transaction production is paused until member migration finality")]
    MigrationFinalizing,
    #[error(transparent)]
    Signing(#[from] SigningError),
    #[error(transparent)]
    Voting(#[from] VotingError),
    #[error(transparent)]
    VotingExecution(#[from] super::voting_execution::VotingExecutionError),
    #[error(transparent)]
    Asset(#[from] AssetError),
    #[error(transparent)]
    UserRequest(#[from] super::user_requests::UserRequestError),
    #[error(transparent)]
    Burning(#[from] BurningError),
    #[error(transparent)]
    Droplets(#[from] DropletsError),
    #[error(transparent)]
    Indexer(#[from] super::indexer::IndexerError),
    #[error(transparent)]
    Price(#[from] super::prices::PriceError),
    #[error(transparent)]
    Renewal(#[from] super::renewal::RenewalError),
    #[error(transparent)]
    Encoding(#[from] postcard::Error),
}

pub(crate) async fn handle(
    state: NetworkState,
    custom: CustomMsg,
    context: StormContext,
) -> Result<(), HandlerError> {
    let Some(message) = NodeMessage::from_custom(&custom)? else {
        return Ok(());
    };
    let Some(kind) = message.decoded_kind() else {
        return Err(SigningError::InvalidMessage(format!(
            "unknown NodeMessage kind {}",
            message.kind
        ))
        .into());
    };
    if state.is_recovering()
        && matches!(
            kind,
            NodeMessageKind::ExecuteUserRequests
                | NodeMessageKind::ExchangeRewards
                | NodeMessageKind::SigningNonces
                | NodeMessageKind::PartialSignatures
                | NodeMessageKind::BurnExpiredUtxos
                | NodeMessageKind::ExpiredUtxosBurned
                | NodeMessageKind::ExecuteVotingRequest
                | NodeMessageKind::RenewStormUtxos
        )
    {
        return Err(HandlerError::Recovering);
    }
    if state.is_spending_paused()
        && matches!(
            kind,
            NodeMessageKind::ExecuteUserRequests
                | NodeMessageKind::ExchangeRewards
                | NodeMessageKind::SigningNonces
                | NodeMessageKind::PartialSignatures
                | NodeMessageKind::BurnExpiredUtxos
                | NodeMessageKind::ExpiredUtxosBurned
                | NodeMessageKind::ExecuteVotingRequest
                | NodeMessageKind::RenewStormUtxos
        )
    {
        return Err(HandlerError::MigrationFinalizing);
    }
    authorize_sender(
        kind,
        state.coordinator_public_key(),
        context.message_context.peer_public_key,
    )?;

    match kind {
        NodeMessageKind::ExecuteUserRequests => {
            let request: crate::ExecuteUserRequests = message.decode_payload()?;
            require_chain_tip(&state, required_chain_tip(request.chain_tip)?).await?;
            let instructed = state.user_requests().validate_execute(&request).await?;
            state
                .signing()
                .handle_execute_user_requests(
                    message,
                    &context,
                    instructed.as_ref().map(price_hash),
                )
                .await?;
            Ok(())
        }
        NodeMessageKind::BurnExpiredUtxos => {
            let request: BurnExpiredUtxos = message.decode_payload()?;
            let expected_leader = require_current_leader(
                &state,
                &context,
                request.block_height,
                required_chain_tip(request.chain_tip)?,
            )
            .await?;
            state.burning().validate_request(&request).await?;
            state
                .signing()
                .handle_burn_expired_utxos(message, &context, expected_leader)
                .await?;
            Ok(())
        }
        NodeMessageKind::ExchangeRewards => {
            let request: crate::ExchangeRewards = message.decode_payload()?;
            let expected_leader = require_current_leader(
                &state,
                &context,
                request.block_height,
                required_chain_tip(request.chain_tip)?,
            )
            .await?;
            if request.final_tx.is_some() {
                state
                    .droplets()
                    .observe_broadcast(&request, expected_leader)
                    .await?;
                return Ok(());
            }
            let exchange = state
                .droplets()
                .validate_request(&request, expected_leader)
                .await?;
            state
                .droplets()
                .lock_exchange(&exchange, request.block_height, &request.tx)
                .await?;
            if let Err(error) = state
                .signing()
                .handle_exchange_rewards(message, &context, expected_leader)
                .await
            {
                state
                    .droplets()
                    .unlock_exchange(exchange.member, request.block_height)
                    .await?;
                return Err(error.into());
            }
            Ok(())
        }
        NodeMessageKind::ExpiredUtxosBurned => {
            let notification: ExpiredUtxosBurned = message.decode_payload()?;
            require_current_leader(
                &state,
                &context,
                notification.block_height,
                required_chain_tip(notification.chain_tip)?,
            )
            .await?;
            state.burning().observe_broadcast(&notification).await?;
            Ok(())
        }
        NodeMessageKind::AttestPrice => {
            state.prices().handle_attestation(message, &context).await?;
            Ok(())
        }
        NodeMessageKind::NetworkAssets => {
            let storm_tree_root = state.signing().storm_tree_root().await.ok();
            state
                .assets()
                .handle_announcement(message, &context, storm_tree_root)
                .await?;
            Ok(())
        }
        NodeMessageKind::NetworkVoteRequest => {
            state
                .voting()
                .handle_request(message, &context, state.block_height())
                .await?;
            Ok(())
        }
        NodeMessageKind::ApproveVotingRequest => {
            state
                .voting()
                .handle_approval(message, &context, state.block_height())
                .await?;
            Ok(())
        }
        NodeMessageKind::AskAboutVotings => {
            state
                .voting()
                .handle_synchronization(message, &context, state.block_height())
                .await?;
            Ok(())
        }
        NodeMessageKind::ExecuteVotingRequest => {
            let request_hash = message.linked_to.ok_or_else(|| {
                super::voting_execution::VotingExecutionError::Invalid(
                    "voting execution does not link to a voting request".into(),
                )
            })?;
            let request: ExecuteVotingRequest = message.decode_payload()?;
            let chain_tip = required_chain_tip(request.chain_tip)?;
            if request.final_tx.is_none() {
                require_chain_tip(&state, chain_tip).await?;
            }
            let peers = context.storm_handle.peers().await;
            let current_members = super::voting_member_keys(&peers)?;
            authorize_voting_executor(&current_members, context.message_context.peer_public_key)?;
            let Some(vote) = state.voting().get(request_hash).await? else {
                if request.final_tx.is_some() {
                    tracing::debug!(request_hash = %hex::encode(request_hash), "ignored execution notice for an unknown vote");
                    return Ok(());
                }
                return Err(
                    super::voting_execution::VotingExecutionError::UnknownRequest(hex::encode(
                        request_hash,
                    ))
                    .into(),
                );
            };
            if request.final_tx.is_some() {
                if vote.status == VotingStatus::Executed {
                    return Ok(());
                }
                require_canonical_anchor(&state, chain_tip)?;
            }
            if let Some(target_members) =
                super::member_migration_target(&vote.request, &current_members)?
            {
                state
                    .ensure_member_migration(&context.storm_handle, request_hash, target_members)
                    .await
                    .map_err(|error| {
                        super::voting_execution::VotingExecutionError::Invalid(error.to_string())
                    })?;
                if !context.storm_handle.local_member_migration_ready().await {
                    return Err(
                        super::voting_execution::VotingExecutionError::MemberMigrationNotReady
                            .into(),
                    );
                }
            }
            if request.final_tx.is_some() {
                state
                    .voting_execution()
                    .observe_broadcast(
                        request_hash,
                        &request,
                        &current_members,
                        state.block_height(),
                    )
                    .await?;
                return Ok(());
            }
            state
                .voting_execution()
                .begin(
                    request_hash,
                    &request,
                    state.block_height(),
                    &current_members,
                )
                .await?;
            state
                .signing()
                .handle_execute_voting_request(message, &context)
                .await?;
            Ok(())
        }
        NodeMessageKind::ProtocolSettings => {
            let settings: ProtocolSettings = message.decode_payload()?;
            let sender = context.message_context.peer_public_key;
            let peer = hex::encode(sender);
            match state.record_peer_settings(sender, &settings) {
                Some(mismatches) if mismatches.is_empty() => {
                    tracing::info!(%peer, "peer protocol settings now match");
                }
                Some(mismatches) => {
                    tracing::error!(
                        %peer,
                        mismatches = %mismatches.join(", "),
                        "peer protocol settings differ; rounds involving it will be rejected"
                    );
                }
                None => {}
            }
            Ok(())
        }
        NodeMessageKind::RenewStormUtxos => {
            let request: RenewStormUtxos = message.decode_payload()?;
            require_chain_tip(&state, required_chain_tip(request.chain_tip)?).await?;
            if request.final_tx.is_some() {
                state.renewal().observe_broadcast(&request).await?;
                return Ok(());
            }
            state.renewal().validate_request(&request).await?;
            state
                .signing()
                .handle_renew_storm_utxos(message, &context)
                .await?;
            Ok(())
        }
        NodeMessageKind::SigningNonces => {
            state
                .signing()
                .handle_signing_nonces(message, &context)
                .await?;
            Ok(())
        }
        NodeMessageKind::PartialSignatures => {
            state
                .signing()
                .handle_partial_signatures(message, &context)
                .await?;
            Ok(())
        }
    }
}

pub(super) fn authorize_voting_executor(
    current_members: &std::collections::BTreeSet<[u8; 32]>,
    sender: [u8; 33],
) -> Result<(), SigningError> {
    let sender = secp256k1::PublicKey::from_slice(&sender)
        .map_err(|error| SigningError::UnauthorizedMessage(error.to_string()))?
        .x_only_public_key()
        .0
        .serialize();
    if !current_members.contains(&sender) {
        return Err(SigningError::UnauthorizedMessage(
            "only a current network member may execute a voting request".into(),
        ));
    }
    Ok(())
}

async fn require_current_leader(
    state: &NetworkState,
    context: &StormContext,
    block_height: u64,
    chain_tip: ChainTip,
) -> Result<[u8; 33], HandlerError> {
    if chain_tip.height != block_height {
        return Err(SigningError::UnauthorizedMessage(
            "leader message block height does not match its chain anchor".into(),
        )
        .into());
    }
    let expected = leader::leader_for_height(&context.storm_handle.peers().await, block_height)
        .ok_or_else(|| SigningError::UnauthorizedMessage("network has no leader".into()))?;
    authorize_leader_sender(expected, context.message_context.peer_public_key)?;
    require_chain_tip(state, chain_tip).await?;

    Ok(expected)
}

fn required_chain_tip(chain_tip: Option<ChainTip>) -> Result<ChainTip, SigningError> {
    chain_tip.ok_or_else(|| {
        SigningError::UnauthorizedMessage("signing request has no canonical chain anchor".into())
    })
}

async fn require_chain_tip(state: &NetworkState, chain_tip: ChainTip) -> Result<(), HandlerError> {
    require_current_tip(chain_tip.height, state.indexer().tip()?)?;
    require_current_hash(chain_tip.hash, state.indexer().hash_at(chain_tip.height)?)?;

    state.indexer().sync().await?;
    let indexed = state.indexer().chain_tip().await?;
    state.set_block_height(indexed.height);
    require_current_tip(chain_tip.height, indexed.height)?;
    require_current_hash(chain_tip.hash, indexed.hash)?;
    Ok(())
}

fn require_canonical_anchor(state: &NetworkState, chain_tip: ChainTip) -> Result<(), HandlerError> {
    let local_hash = if chain_tip.height <= state.indexer().tip()? {
        Some(state.indexer().hash_at(chain_tip.height)?)
    } else {
        None
    };
    canonical_anchor(chain_tip, local_hash)?;
    Ok(())
}

fn canonical_anchor(chain_tip: ChainTip, local_hash: Option<[u8; 32]>) -> Result<(), SigningError> {
    match local_hash {
        None => Err(SigningError::UnauthorizedMessage(
            "finalized execution anchors a block this node has not seen".into(),
        )),
        Some(hash) if hash != chain_tip.hash => Err(SigningError::UnauthorizedMessage(
            "finalized execution anchors a block outside the canonical chain".into(),
        )),
        Some(_) => Ok(()),
    }
}

fn require_current_tip(block_height: u64, tip: u64) -> Result<(), SigningError> {
    if block_height != tip {
        return Err(SigningError::UnauthorizedMessage(
            "message does not target the current block".into(),
        ));
    }

    Ok(())
}

fn require_current_hash(expected: [u8; 32], actual: [u8; 32]) -> Result<(), SigningError> {
    if expected != actual {
        return Err(SigningError::UnauthorizedMessage(
            "signing request does not target the current block hash".into(),
        ));
    }
    Ok(())
}

fn authorize_leader_sender(expected: [u8; 33], sender: [u8; 33]) -> Result<(), SigningError> {
    if sender != expected {
        return Err(SigningError::UnauthorizedMessage(format!(
            "only network leader {} may send leader-only messages",
            hex::encode(expected)
        )));
    }
    Ok(())
}

fn authorize_sender(
    kind: NodeMessageKind,
    coordinator_public_key: [u8; 33],
    sender_public_key: [u8; 33],
) -> Result<(), SigningError> {
    if kind.requires_coordinator() && sender_public_key != coordinator_public_key {
        return Err(SigningError::UnauthorizedMessage(format!(
            "only coordinator {} may send {kind:?}",
            hex::encode(coordinator_public_key)
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const COORDINATOR: [u8; 33] = [1; 33];
    const MEMBER: [u8; 33] = [2; 33];

    #[test]
    fn current_member_can_execute_another_members_voting_request() {
        let proposer = secp256k1::PublicKey::from_secret_key(
            &secp256k1::SecretKey::from_secret_bytes([1; 32]).unwrap(),
        );
        let executor = secp256k1::PublicKey::from_secret_key(
            &secp256k1::SecretKey::from_secret_bytes([2; 32]).unwrap(),
        );
        let current_members = [
            proposer.x_only_public_key().0.serialize(),
            executor.x_only_public_key().0.serialize(),
        ]
        .into_iter()
        .collect();

        authorize_voting_executor(&current_members, proposer.serialize()).unwrap();
        authorize_voting_executor(&current_members, executor.serialize()).unwrap();
    }

    #[test]
    fn non_member_cannot_execute_a_voting_request() {
        let outsider = secp256k1::PublicKey::from_secret_key(
            &secp256k1::SecretKey::from_secret_bytes([3; 32]).unwrap(),
        );
        let error =
            authorize_voting_executor(&Default::default(), outsider.serialize()).unwrap_err();

        assert!(matches!(error, SigningError::UnauthorizedMessage(_)));
        assert!(authorize_voting_executor(&Default::default(), [0; 33]).is_err());
    }

    #[test]
    fn coordinator_can_send_user_request_messages() {
        authorize_sender(
            NodeMessageKind::ExecuteUserRequests,
            COORDINATOR,
            COORDINATOR,
        )
        .unwrap();
    }

    #[test]
    fn member_cannot_send_user_request_messages() {
        let error = authorize_sender(NodeMessageKind::ExecuteUserRequests, COORDINATOR, MEMBER)
            .unwrap_err();

        assert!(matches!(error, SigningError::UnauthorizedMessage(_)));
    }

    #[test]
    fn member_can_send_messages_without_coordinator_restriction() {
        authorize_sender(NodeMessageKind::AttestPrice, COORDINATOR, MEMBER).unwrap();
    }

    #[test]
    fn only_coordinator_can_announce_network_assets() {
        let error =
            authorize_sender(NodeMessageKind::NetworkAssets, COORDINATOR, MEMBER).unwrap_err();

        assert!(matches!(error, SigningError::UnauthorizedMessage(_)));
    }

    #[test]
    fn only_coordinator_can_renew_storm_eyes() {
        let error =
            authorize_sender(NodeMessageKind::RenewStormUtxos, COORDINATOR, MEMBER).unwrap_err();

        assert!(matches!(error, SigningError::UnauthorizedMessage(_)));
        authorize_sender(NodeMessageKind::RenewStormUtxos, COORDINATOR, COORDINATOR).unwrap();
    }

    #[test]
    fn current_leader_can_send_burn_messages() {
        authorize_leader_sender(COORDINATOR, COORDINATOR).unwrap();
    }

    #[test]
    fn non_leader_cannot_send_burn_messages() {
        let error = authorize_leader_sender(COORDINATOR, MEMBER).unwrap_err();

        assert!(matches!(error, SigningError::UnauthorizedMessage(_)));
    }

    #[test]
    fn non_leader_cannot_send_exchange_messages() {
        let error = authorize_leader_sender(COORDINATOR, MEMBER).unwrap_err();

        assert!(matches!(error, SigningError::UnauthorizedMessage(_)));
    }

    #[test]
    fn leader_messages_must_target_the_current_tip() {
        require_current_tip(42, 42).unwrap();

        let error = require_current_tip(43, 42).unwrap_err();
        assert!(matches!(error, SigningError::UnauthorizedMessage(_)));
    }

    #[test]
    fn finalized_executions_accept_any_seen_canonical_anchor() {
        let anchor = ChainTip {
            height: 40,
            hash: [4; 32],
        };

        canonical_anchor(anchor, Some([4; 32])).unwrap();

        let fork = canonical_anchor(anchor, Some([5; 32])).unwrap_err();
        assert!(
            matches!(fork, SigningError::UnauthorizedMessage(reason) if reason.contains("outside"))
        );

        let unseen = canonical_anchor(anchor, None).unwrap_err();
        assert!(
            matches!(unseen, SigningError::UnauthorizedMessage(reason) if reason.contains("not seen"))
        );
    }

    #[test]
    fn signing_messages_require_a_chain_anchor() {
        let error = required_chain_tip(None).unwrap_err();

        assert!(matches!(error, SigningError::UnauthorizedMessage(_)));
    }

    #[test]
    fn signing_messages_must_target_the_current_block_hash() {
        require_current_hash([4; 32], [4; 32]).unwrap();

        let error = require_current_hash([4; 32], [5; 32]).unwrap_err();
        assert!(matches!(error, SigningError::UnauthorizedMessage(_)));
    }
}
