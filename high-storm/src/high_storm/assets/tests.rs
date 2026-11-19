use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};

use crate::db::Database;
use simplex::simplicityhl::elements::AssetEntropy;

use super::*;

#[test]
fn decodes_rpc_asset_id_to_consensus_bytes() {
    let displayed = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
    let mut expected = hex::decode(displayed).unwrap();
    expected.reverse();

    assert_eq!(
        decode_asset_hash(displayed, "test").unwrap().as_slice(),
        expected
    );
}

#[test]
fn derives_rpc_asset_id_from_decoded_entropy() {
    let asset = decode_asset_hash(
        "667c7d600018fae9173b923c64519cf478f1f61585317db793ddfbc303205a08",
        "test asset",
    )
    .unwrap();
    let entropy = decode_asset_hash(
        "4cab94f3f15a98cbd3eb3d6d6e8db3d7b884084c75e08bab24a3df1cbc27c451",
        "test entropy",
    )
    .unwrap();

    assert_eq!(
        AssetId::from_entropy(AssetEntropy::from_byte_array(entropy)),
        AssetId::from_byte_array(asset)
    );
}

#[test]
fn accepts_only_zero_blinder_funding_utxos() {
    let mut utxo = WalletUtxo {
        txid: "00".repeat(32),
        vout: 0,
        address: "address".into(),
        script_pub_key: String::new(),
        asset: "asset".into(),
        amount: 1.0,
        spendable: true,
        amountblinder: "0".repeat(64),
        assetblinder: "0".repeat(64),
    };
    assert!(utxo.is_explicit());

    utxo.amountblinder = "1".repeat(64);
    assert!(!utxo.is_explicit());
}

#[test]
fn rejects_confidential_issuance_outputs() {
    let transaction = DecodedTransaction {
        txid: "00".repeat(32),
        vout: vec![DecodedOutput {
            index: 2,
            asset_commitment: Some("0a".repeat(33)),
            nonce: None,
            value_commitment: None,
        }],
    };

    assert!(matches!(
        ensure_explicit_outputs(&transaction),
        Err(AssetError::ConfidentialOutput(2))
    ));
}

#[test]
fn creates_six_initial_storm_eye_outputs_with_the_full_supply() {
    let asset_id = AssetId::from_byte_array([1; 32]);
    let contract_script = Script::from(vec![0x51]);
    let mut transaction = Transaction {
        version: 2,
        lock_time: simplex::simplicityhl::elements::LockTime::ZERO,
        input: Vec::new(),
        output: vec![TxOut {
            asset: simplex::simplicityhl::elements::confidential::Asset::Explicit(asset_id),
            value: simplex::simplicityhl::elements::confidential::Value::Explicit(STORM_EYE_SUPPLY),
            nonce: simplex::simplicityhl::elements::confidential::Nonce::Null,
            script_pubkey: contract_script.clone(),
            witness: Default::default(),
        }],
    };

    ElementsAssetIssuer::split_initial_storm_eye_output(
        &mut transaction,
        asset_id,
        &contract_script,
    )
    .unwrap();

    assert_eq!(transaction.output.len(), INITIAL_STORM_EYE_UTXO_COUNT);
    assert_eq!(
        transaction
            .output
            .iter()
            .map(|output| output.value.explicit().unwrap())
            .sum::<u64>(),
        STORM_EYE_SUPPLY
    );
    assert!(transaction.output.iter().all(|output| {
        output.asset.explicit() == Some(asset_id) && output.script_pubkey == contract_script
    }));
}

#[derive(Clone)]
struct FakeIssuer {
    prepared: Arc<AtomicUsize>,
    broadcast: Arc<AtomicUsize>,
    pending: PendingNetworkAsset,
}

impl FakeIssuer {
    fn new() -> Self {
        Self {
            prepared: Arc::new(AtomicUsize::new(0)),
            broadcast: Arc::new(AtomicUsize::new(0)),
            pending: PendingNetworkAsset {
                asset: NetworkAsset {
                    kind: STORM_EYE_KIND.to_string(),
                    name: STORM_EYE_NAME.to_string(),
                    asset_id: [1; 32],
                    reissuance_token_id: None,
                    entropy: Some([2; 32]),
                    issuance_txid: [3; 32],
                    contract_script: vec![0x51],
                    contract_data: None,
                    supply: STORM_EYE_SUPPLY,
                    created_at_block: 42,
                },
                issuance_tx: vec![4; 64],
            },
        }
    }
}

impl AssetIssuer for FakeIssuer {
    fn prepare(
        &self,
        _storm_tree_root: [u8; 32],
        _initial_members: &[[u8; 32]],
    ) -> Result<PendingNetworkAsset, AssetError> {
        self.prepared.fetch_add(1, Ordering::SeqCst);
        Ok(self.pending.clone())
    }

    fn broadcast(&self, transaction: &[u8], expected_txid: [u8; 32]) -> Result<(), AssetError> {
        assert_eq!(transaction, self.pending.issuance_tx);
        assert_eq!(expected_txid, self.pending.asset.issuance_txid);
        self.broadcast.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
}

#[derive(Clone)]
struct FakeTickAssetIssuer {
    prepared: Arc<AtomicUsize>,
    broadcast: Arc<AtomicUsize>,
    pending: PendingNetworkAsset,
}

impl FakeTickAssetIssuer {
    fn new() -> Self {
        Self {
            prepared: Arc::new(AtomicUsize::new(0)),
            broadcast: Arc::new(AtomicUsize::new(0)),
            pending: PendingNetworkAsset {
                asset: NetworkAsset {
                    kind: TICK_ASSET_KIND.to_string(),
                    name: TICK_ASSET_NAME.to_string(),
                    asset_id: [5; 32],
                    reissuance_token_id: Some([6; 32]),
                    entropy: Some([7; 32]),
                    issuance_txid: [8; 32],
                    contract_script: vec![0x51],
                    contract_data: None,
                    supply: REISSUABLE_ASSET_SUPPLY,
                    created_at_block: 43,
                },
                issuance_tx: vec![9; 64],
            },
        }
    }
}

impl AssetIssuer for FakeTickAssetIssuer {
    fn prepare(
        &self,
        _storm_tree_root: [u8; 32],
        _initial_members: &[[u8; 32]],
    ) -> Result<PendingNetworkAsset, AssetError> {
        unreachable!("reissuable asset initialization uses prepare_reissuable_asset")
    }

    fn broadcast(&self, transaction: &[u8], expected_txid: [u8; 32]) -> Result<(), AssetError> {
        assert_eq!(transaction, self.pending.issuance_tx);
        assert_eq!(expected_txid, self.pending.asset.issuance_txid);
        self.broadcast.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
}

impl ReissuableAssetIssuer for FakeTickAssetIssuer {
    fn prepare_reissuable_asset(
        &self,
        _kind: &str,
        _name: &str,
        _storm_eye_asset_id: [u8; 32],
    ) -> Result<PendingNetworkAsset, AssetError> {
        self.prepared.fetch_add(1, Ordering::SeqCst);
        Ok(self.pending.clone())
    }
}

async fn assets() -> Assets {
    let database = Database::connect("sqlite::memory:", 1).await.unwrap();
    Assets::new(
        database.network_assets(),
        ElementsRpcConfig {
            url: "http://127.0.0.1:1".into(),
            username: String::new(),
            password: String::new(),
            wallet: "funded-key".into(),
        },
    )
}

mod announcement_verification {
    use super::*;
    use secp256k1_zkp::Keypair;
    use simplex::simplicityhl::elements::{AssetIssuance, LockTime, OutPoint, Txid, confidential};

    fn members(bytes: &[u8]) -> Vec<[u8; 32]> {
        let secp = Secp256k1::new();
        bytes
            .iter()
            .map(|byte| {
                let secret = SecretKey::from_slice(&[*byte; 32]).unwrap();
                Keypair::from_secret_key(&secp, &secret)
                    .x_only_public_key()
                    .0
                    .serialize()
            })
            .collect()
    }

    fn with_storm_eye_state(asset: &NetworkAsset, root: [u8; 32], rescue: u32) -> NetworkAsset {
        let mut asset = asset.clone();
        asset.contract_data = Some(
            postcard::to_stdvec(&StormEyeContractData {
                storm_tree_root: root,
                rescue_height: rescue,
                rescue_output_script_hash: [9; 32],
            })
            .unwrap(),
        );
        asset.contract_script = storm_eye_program(&asset)
            .unwrap()
            .get_script_pubkey(&SimplicityNetwork::default_regtest())
            .into_bytes();
        asset
    }

    fn issuing_input(amount: u64, inflation_keys: u64) -> TxIn {
        let explicit = |value| {
            if value == 0 {
                confidential::Value::Null
            } else {
                confidential::Value::Explicit(value)
            }
        };
        TxIn {
            previous_output: OutPoint::new(Txid::from_byte_array([4; 32]), 1),
            asset_issuance: AssetIssuance {
                amount: explicit(amount),
                inflation_keys: explicit(inflation_keys),
                ..Default::default()
            },
            ..Default::default()
        }
    }

    fn output(asset: AssetId, value: u64, script: Script) -> TxOut {
        TxOut {
            asset: confidential::Asset::Explicit(asset),
            value: confidential::Value::Explicit(value),
            nonce: confidential::Nonce::Null,
            script_pubkey: script,
            witness: Default::default(),
        }
    }

    /// A genesis Storm Eye issued to three members at block 100.
    fn storm_eye() -> (NetworkAsset, ConfirmedIssuance, [u8; 32]) {
        let members = members(&[1, 2, 3]);
        let root = StormTree::new(members.clone()).unwrap().root();
        let input = issuing_input(STORM_EYE_SUPPLY, 0);
        let (asset_id, _) = input.issuance_ids();
        let entropy = AssetId::generate_asset_entropy(
            input.previous_output,
            input.asset_issuance.asset_entropy.into_contract_hash(),
        );
        let template = NetworkAsset {
            kind: STORM_EYE_KIND.into(),
            name: STORM_EYE_NAME.into(),
            asset_id: asset_id.to_byte_array(),
            reissuance_token_id: None,
            entropy: Some(entropy.to_byte_array()),
            issuance_txid: [0; 32],
            contract_script: Vec::new(),
            contract_data: None,
            supply: STORM_EYE_SUPPLY,
            created_at_block: 100,
        };
        let asset = with_storm_eye_state(&template, root, 100 + RESCUE_BLOCKS as u32);
        let script = Script::from(asset.contract_script.clone());
        let mut outputs = (0..INITIAL_STORM_EYE_UTXO_COUNT as u64)
            .map(|index| output(asset_id, 1_666 + u64::from(index < 4), script.clone()))
            .collect::<Vec<_>>();
        outputs.push(TxOut {
            script_pubkey: initial_members_script(&members).unwrap(),
            ..output(AssetId::from_byte_array([5; 32]), 0, Script::new())
        });
        let issuance = ConfirmedIssuance {
            transaction: Transaction {
                version: 2,
                lock_time: LockTime::ZERO,
                input: vec![input],
                output: outputs,
            },
            block_height: 101,
        };
        (asset, issuance, root)
    }

    fn verify_storm_eye_with(
        asset: &NetworkAsset,
        issuance: &ConfirmedIssuance,
        root: Option<[u8; 32]>,
    ) -> Result<(), AssetError> {
        verify_announced_asset(
            asset,
            issuance,
            None,
            root,
            &SimplicityNetwork::default_regtest(),
        )
    }

    #[test]
    fn accepts_genesis_renewed_and_migrated_storm_eyes() {
        let (genesis, issuance, root) = storm_eye();
        verify_storm_eye_with(&genesis, &issuance, Some(root)).unwrap();

        let renewed = with_storm_eye_state(&genesis, root, 100 + 2 * RESCUE_BLOCKS as u32);
        verify_storm_eye_with(&renewed, &issuance, Some(root)).unwrap();

        let migrated_root = StormTree::new(members(&[1, 2, 4])).unwrap().root();
        let migrated = with_storm_eye_state(&genesis, migrated_root, 100 + RESCUE_BLOCKS as u32);
        verify_storm_eye_with(&migrated, &issuance, Some(migrated_root)).unwrap();
    }

    #[test]
    fn rejects_forged_storm_eye_announcements() {
        let (genesis, issuance, root) = storm_eye();
        let rejected = |asset: &NetworkAsset, issuance: &ConfirmedIssuance, root| {
            assert!(verify_storm_eye_with(asset, issuance, root).is_err());
        };

        // A covenant over someone else's keys, or before this node has a tree.
        rejected(&genesis, &issuance, Some([0; 32]));
        rejected(&genesis, &issuance, None);

        let mut hidden_token = issuance.transaction.clone();
        hidden_token.input[0].asset_issuance.inflation_keys = confidential::Value::Explicit(1);
        rejected(
            &genesis,
            &ConfirmedIssuance {
                transaction: hidden_token,
                block_height: 101,
            },
            Some(root),
        );

        let mut diverted = issuance.transaction.clone();
        diverted.output[0].script_pubkey = Script::from(vec![0x51]);
        rejected(
            &genesis,
            &ConfirmedIssuance {
                transaction: diverted,
                block_height: 101,
            },
            Some(root),
        );

        let mut other_members = issuance.transaction.clone();
        other_members.output.last_mut().unwrap().script_pubkey =
            initial_members_script(&members(&[4, 5, 6])).unwrap();
        rejected(
            &genesis,
            &ConfirmedIssuance {
                transaction: other_members,
                block_height: 101,
            },
            Some(root),
        );

        let off_schedule = with_storm_eye_state(&genesis, root, 101 + RESCUE_BLOCKS as u32);
        rejected(&off_schedule, &issuance, Some(root));

        let mut wrong_script = genesis.clone();
        wrong_script.contract_script = vec![0x51];
        rejected(&wrong_script, &issuance, Some(root));

        let mut wrong_entropy = genesis.clone();
        wrong_entropy.entropy = Some([1; 32]);
        rejected(&wrong_entropy, &issuance, Some(root));

        rejected(
            &genesis,
            &ConfirmedIssuance {
                transaction: issuance.transaction.clone(),
                block_height: 99,
            },
            Some(root),
        );
    }

    #[tokio::test]
    #[ignore = "requires HIGH_STORM_TEST_ASSET_DATABASE_URL and HIGH_STORM_TEST_RPC_URL of a live network"]
    async fn verifies_a_live_networks_issued_assets() {
        let database = Database::connect(
            &std::env::var("HIGH_STORM_TEST_ASSET_DATABASE_URL").unwrap(),
            1,
        )
        .await
        .unwrap();
        let store = database.network_assets();
        let client = Client::new(
            &std::env::var("HIGH_STORM_TEST_RPC_URL").unwrap(),
            Auth::UserPass("high-storm".into(), "high-storm".into()),
        )
        .unwrap();
        let storm_eye = store.get(STORM_EYE_KIND).await.unwrap().unwrap();
        let root = storm_eye_contract_data(&storm_eye).unwrap().storm_tree_root;
        let mut reissuable = Vec::new();
        for kind in [TICK_ASSET_KIND, ORACLE_VERIFIER_KIND] {
            reissuable.push(store.get(kind).await.unwrap().unwrap());
        }

        tokio::task::spawn_blocking(move || {
            let chain: ChainInfo = client.call("getblockchaininfo", &[]).unwrap();
            let network = simplicity_network(&chain.chain).unwrap();
            let issuance = confirmed_issuance(&client, storm_eye.issuance_txid).unwrap();
            verify_announced_asset(&storm_eye, &issuance, None, Some(root), &network).unwrap();
            for asset in reissuable {
                let issuance = confirmed_issuance(&client, asset.issuance_txid).unwrap();
                verify_announced_asset(&asset, &issuance, Some(&storm_eye), None, &network)
                    .unwrap();
            }
        })
        .await
        .unwrap();
    }

    /// A Tick issued empty, its single token blinded to the Treasury.
    fn tick(storm_eye: &NetworkAsset) -> (NetworkAsset, ConfirmedIssuance) {
        let network = SimplicityNetwork::default_regtest();
        let treasury_script = TreasuryProgram::new(&TreasuryArguments {
            storm_eye_asset_id: storm_eye.asset_id,
        })
        .get_script_pubkey(&network);
        let input = issuing_input(0, REISSUANCE_TOKEN_SUPPLY);
        let (asset_id, token_id) = input.issuance_ids();
        let entropy = AssetId::generate_asset_entropy(
            input.previous_output,
            input.asset_issuance.asset_entropy.into_contract_hash(),
        );
        let funding = AssetId::from_byte_array([5; 32]);
        let (token_output, _, _, _) = TxOut::new_last_confidential(
            &mut secp256k1_zkp::rand::thread_rng(),
            &Secp256k1::new(),
            REISSUANCE_TOKEN_SUPPLY,
            token_id,
            treasury_script.clone(),
            PublicKey::from_secret_key(&Secp256k1::new(), &treasury_blinding_secret()),
            &[
                TxOutSecrets::new(
                    funding,
                    AssetBlindingFactor::zero(),
                    10_000,
                    ValueBlindingFactor::zero(),
                ),
                TxOutSecrets::new(
                    token_id,
                    AssetBlindingFactor::zero(),
                    REISSUANCE_TOKEN_SUPPLY,
                    ValueBlindingFactor::zero(),
                ),
            ],
            &[],
        )
        .unwrap();
        let transaction = Transaction {
            version: 2,
            lock_time: LockTime::ZERO,
            input: vec![input],
            output: vec![
                token_output,
                output(funding, 9_000, Script::from(vec![0x51])),
            ],
        };
        let asset = NetworkAsset {
            kind: TICK_ASSET_KIND.into(),
            name: TICK_ASSET_NAME.into(),
            asset_id: asset_id.to_byte_array(),
            reissuance_token_id: Some(token_id.to_byte_array()),
            entropy: Some(entropy.to_byte_array()),
            issuance_txid: [0; 32],
            contract_script: treasury_script.into_bytes(),
            contract_data: Some(
                postcard::to_stdvec(&TickAssetContractData {
                    issuance_tx: encode::serialize(&transaction),
                    token_output_index: 0,
                })
                .unwrap(),
            ),
            supply: REISSUABLE_ASSET_SUPPLY,
            created_at_block: 100,
        };
        (
            asset,
            ConfirmedIssuance {
                transaction,
                block_height: 101,
            },
        )
    }

    fn verify_tick_with(
        asset: &NetworkAsset,
        issuance: &ConfirmedIssuance,
        storm_eye: &NetworkAsset,
    ) -> Result<(), AssetError> {
        verify_announced_asset(
            asset,
            issuance,
            Some(storm_eye),
            None,
            &SimplicityNetwork::default_regtest(),
        )
    }

    #[test]
    fn accepts_only_treasury_held_reissuance_tokens() {
        let (storm_eye, _, _) = storm_eye();
        let (asset, issuance) = tick(&storm_eye);
        verify_tick_with(&asset, &issuance, &storm_eye).unwrap();

        // Announced before the Storm Eye it must be verified against.
        assert!(
            verify_announced_asset(
                &asset,
                &issuance,
                None,
                None,
                &SimplicityNetwork::default_regtest()
            )
            .is_err()
        );

        let mut other_storm_eye = storm_eye.clone();
        other_storm_eye.asset_id = [8; 32];
        assert!(verify_tick_with(&asset, &issuance, &other_storm_eye).is_err());

        let mut kept_token = issuance.transaction.clone();
        kept_token.output[0].script_pubkey = Script::from(vec![0x51]);
        let mut diverted = asset.clone();
        diverted.contract_data = Some(
            postcard::to_stdvec(&TickAssetContractData {
                issuance_tx: encode::serialize(&kept_token),
                token_output_index: 0,
            })
            .unwrap(),
        );
        assert!(
            verify_tick_with(
                &diverted,
                &ConfirmedIssuance {
                    transaction: kept_token,
                    block_height: 101,
                },
                &storm_eye,
            )
            .is_err()
        );

        let mut wrong_token = asset.clone();
        wrong_token.reissuance_token_id = Some([7; 32]);
        assert!(verify_tick_with(&wrong_token, &issuance, &storm_eye).is_err());

        let mut minted = issuance.transaction.clone();
        minted.input[0].asset_issuance.amount = confidential::Value::Explicit(1);
        assert!(
            verify_tick_with(
                &asset,
                &ConfirmedIssuance {
                    transaction: minted,
                    block_height: 101,
                },
                &storm_eye,
            )
            .is_err()
        );
    }
}

#[tokio::test]
async fn creates_and_activates_storm_eye_once() {
    let assets = assets().await;
    let issuer = FakeIssuer::new();

    let created = assets
        .ensure_storm_eye(issuer.clone(), [5; 32], vec![[1; 32], [2; 32]])
        .await
        .unwrap();
    let existing = assets
        .ensure_storm_eye(issuer.clone(), [6; 32], vec![[1; 32], [2; 32]])
        .await
        .unwrap();

    assert_eq!(created, issuer.pending.asset);
    assert_eq!(existing, issuer.pending.asset);
    assert_eq!(issuer.prepared.load(Ordering::SeqCst), 1);
    assert_eq!(issuer.broadcast.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn creates_and_activates_tick_asset_once() {
    let assets = assets().await;
    let issuer = FakeTickAssetIssuer::new();

    let created = assets
        .ensure_reissuable_asset(TICK_ASSET_KIND, TICK_ASSET_NAME, issuer.clone(), [1; 32])
        .await
        .unwrap();
    let existing = assets
        .ensure_reissuable_asset(TICK_ASSET_KIND, TICK_ASSET_NAME, issuer.clone(), [2; 32])
        .await
        .unwrap();

    assert_eq!(created, issuer.pending.asset);
    assert_eq!(created.supply, 0);
    assert_eq!(created.reissuance_token_id, Some([6; 32]));
    assert_eq!(existing, issuer.pending.asset);
    assert_eq!(issuer.prepared.load(Ordering::SeqCst), 1);
    assert_eq!(issuer.broadcast.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn rebroadcasts_persisted_pending_transaction() {
    let assets = assets().await;
    let issuer = FakeIssuer::new();
    assets.store.insert_pending(&issuer.pending).await.unwrap();

    let created = assets
        .ensure_storm_eye(issuer.clone(), [5; 32], vec![[1; 32], [2; 32]])
        .await
        .unwrap();

    assert_eq!(created, issuer.pending.asset);
    assert_eq!(issuer.prepared.load(Ordering::SeqCst), 0);
    assert_eq!(issuer.broadcast.load(Ordering::SeqCst), 1);
    assert!(
        assets
            .store
            .get_pending(STORM_EYE_KIND)
            .await
            .unwrap()
            .is_none()
    );
}

#[test]
fn initial_members_marker_is_canonical_and_round_trips() {
    let script = initial_members_script(&[[3; 32], [1; 32], [3; 32], [2; 32]]).unwrap();

    assert_eq!(
        initial_members_from_script(&script).unwrap(),
        Some(vec![[1; 32], [2; 32], [3; 32]])
    );
    assert_eq!(
        initial_members_from_script(&Script::new_op_return(b"other")).unwrap(),
        None
    );
}

#[test]
fn migrated_members_marker_includes_the_proposer() {
    let proposer = [4; 32];
    let script = migrated_members_script(&[[3; 32], [1; 32], [2; 32]], proposer).unwrap();

    assert_eq!(
        migrated_members_proposer_from_script(&script),
        Some(proposer)
    );
    assert!(initial_members_from_script(&script).is_err());
}

#[test]
fn malformed_migrated_member_markers_are_not_markers() {
    let mut count_mismatch = Vec::from(INITIAL_MEMBERS_MAGIC);
    count_mismatch.push(MIGRATED_MEMBERS_VERSION);
    count_mismatch.extend_from_slice(&u16::MAX.to_be_bytes());
    assert_eq!(
        migrated_members_proposer_from_script(&Script::new_op_return(&count_mismatch)),
        None
    );

    let mut unordered = Vec::from(INITIAL_MEMBERS_MAGIC);
    unordered.push(MIGRATED_MEMBERS_VERSION);
    unordered.extend_from_slice(&2u16.to_be_bytes());
    unordered.extend_from_slice(&[2; 32]);
    unordered.extend_from_slice(&[1; 32]);
    unordered.extend_from_slice(&[4; 32]);
    assert_eq!(
        migrated_members_proposer_from_script(&Script::new_op_return(&unordered)),
        None
    );

    let mut empty_count = Vec::from(INITIAL_MEMBERS_MAGIC);
    empty_count.push(MIGRATED_MEMBERS_VERSION);
    empty_count.extend_from_slice(&0u16.to_be_bytes());
    empty_count.extend_from_slice(&[4; 32]);
    assert_eq!(
        migrated_members_proposer_from_script(&Script::new_op_return(&empty_count)),
        None
    );
}

#[test]
fn rejects_malformed_initial_member_markers() {
    assert!(initial_members_script(&[]).is_err());

    let mut count_mismatch = Vec::from(INITIAL_MEMBERS_MAGIC);
    count_mismatch.push(INITIAL_MEMBERS_VERSION);
    count_mismatch.extend_from_slice(&2u16.to_be_bytes());
    count_mismatch.extend_from_slice(&[1; 32]);
    assert!(initial_members_from_script(&Script::new_op_return(&count_mismatch)).is_err());

    let mut unordered = Vec::from(INITIAL_MEMBERS_MAGIC);
    unordered.push(INITIAL_MEMBERS_VERSION);
    unordered.extend_from_slice(&2u16.to_be_bytes());
    unordered.extend_from_slice(&[2; 32]);
    unordered.extend_from_slice(&[1; 32]);
    assert!(initial_members_from_script(&Script::new_op_return(&unordered)).is_err());
}

#[test]
fn encodes_rescue_height_in_the_contract_storage_word() {
    let slot = rescue_block_slot(0x1234_5678);

    assert_eq!(&slot[..28], &[0; 28]);
    assert_eq!(&slot[28..], &[0x12, 0x34, 0x56, 0x78]);
}
