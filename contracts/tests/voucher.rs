//! 3. Voucher contract (spec §3.4).

#[path = "common/mod.rs"]
mod common;

use common::{assert_covenant_rejects, issue_asset, wait_for_confirmation};

use simplex::provider::SimplicityNetwork;
use simplex::simplicityhl::elements::{
    AssetId, OutPoint, Script, Sequence, TxOut, Txid, confidential,
    secp256k1_zkp::{Keypair, Secp256k1, SecretKey},
};
use simplex::transaction::partial_input::IssuanceInput;
use simplex::transaction::utxo::UTXO;
use simplex::transaction::{FinalTransaction, PartialInput, PartialOutput, RequiredSignature};
use simplex::utils::hash_script;

use contracts::voucher::{
    PERMISSIONLESS_BURN_DELAY_INTERVALS, Voucher, VoucherAuthMethod, VoucherParameters,
    VoucherSpendPath,
};

const STORM_EYE_SUPPLY: u64 = 10_000;
const AUTH_ASSET_SUPPLY: u64 = 10_000;

/// Timestamp encoded in amount.
const VOUCHER_TIMESTAMP: u64 = 1_700_000_000;

/// An untagged OP_RETURN, as the network's aggregated burn uses.
fn op_return_output(amount: u64, asset: AssetId) -> PartialOutput {
    PartialOutput::new(Script::new_op_return(&[]), amount, asset)
}

/// The burn a user-path spend of the voucher at `voucher_input_index` must pay into.
fn burn_output(voucher_input_index: u32, amount: u64, asset: AssetId) -> PartialOutput {
    PartialOutput::new(Voucher::get_burn_script(voucher_input_index), amount, asset)
}

struct VoucherFixture {
    voucher: Voucher,
    storm_eye_asset: AssetId,
    voucher_asset: AssetId,
    /// Carries `AUTH_ASSET_ID`, and sits at the signer's address.
    auth_asset: AssetId,
}

/// Which auth method to configure a `VoucherFixture` for.
enum AuthMethodKind {
    Asset,
    Script,
    Signature,
}

impl VoucherFixture {
    fn new(context: &simplex::TestContext, kind: AuthMethodKind) -> anyhow::Result<Self> {
        let signer = context.get_default_signer();

        let storm_eye_asset = issue_asset(context, STORM_EYE_SUPPLY)?;
        let auth_asset = issue_asset(context, AUTH_ASSET_SUPPLY)?;

        let auth_method = match kind {
            AuthMethodKind::Asset => VoucherAuthMethod::Asset {
                auth_asset_id: auth_asset,
            },
            AuthMethodKind::Script => VoucherAuthMethod::Script {
                auth_script_hash: hash_script(&signer.get_address().script_pubkey()),
            },
            AuthMethodKind::Signature => VoucherAuthMethod::Signature {
                auth_pubkey: signer.get_schnorr_public_key().serialize(),
            },
        };

        let voucher = Voucher::new(VoucherParameters {
            storm_eye_asset_id: storm_eye_asset,
            auth_method,
            network: *context.get_network(),
        });

        let voucher_asset = issue_voucher(context, &voucher, VOUCHER_TIMESTAMP)?;

        Ok(Self {
            voucher,
            storm_eye_asset,
            voucher_asset,
            auth_asset,
        })
    }

    fn auth_utxo(&self, context: &simplex::TestContext) -> anyhow::Result<UTXO> {
        Ok(context
            .get_default_signer()
            .get_utxos_asset(self.auth_asset)?[0]
            .clone())
    }

    fn voucher_utxos(&self, context: &simplex::TestContext) -> anyhow::Result<Vec<UTXO>> {
        Ok(context
            .get_default_provider()
            .fetch_scripthash_utxos(&self.voucher.get_script_pubkey())?)
    }

    fn storm_eye_utxo(&self, context: &simplex::TestContext) -> anyhow::Result<UTXO> {
        Ok(context
            .get_default_signer()
            .get_utxos_asset(self.storm_eye_asset)?[0]
            .clone())
    }

    /// Spends `voucher_utxo` at input 0 with `auth_utxo` at input 1 and `burn_output` at output 0.
    fn burn_transaction(
        &self,
        context: &simplex::TestContext,
        voucher_utxo: &UTXO,
        auth_utxo: &UTXO,
        path: VoucherSpendPath,
        burn_output: PartialOutput,
    ) -> anyhow::Result<FinalTransaction> {
        let signer = context.get_default_signer();

        let mut ft = FinalTransaction::new();

        // Input 0: the Voucher UTXO under the covenant.
        self.voucher.attach_spend(&mut ft, voucher_utxo, path);
        // Input 1: whatever is meant to authorise the spend.
        ft.add_input(
            PartialInput::new(auth_utxo.clone()),
            RequiredSignature::NativeEcdsa,
        );

        // Output 0: the burn the covenant inspects.
        ft.add_output(burn_output);
        // Output 1: the auth UTXO handed back, untouched.
        ft.add_output(PartialOutput::new(
            signer.get_address().script_pubkey(),
            auth_utxo.explicit_amount(),
            auth_utxo.explicit_asset(),
        ));

        Ok(ft)
    }
}

/// Issues the Voucher directly to the covenant, with the timestamp as its amount.
fn issue_voucher(
    context: &simplex::TestContext,
    voucher: &Voucher,
    amount: u64,
) -> anyhow::Result<AssetId> {
    let signer = context.get_default_signer();
    let funding_utxo = signer.get_utxos_asset(context.get_network().policy_asset())?[0].clone();

    let mut ft = FinalTransaction::new();

    let issuance = ft.add_issuance_input(
        PartialInput::new(funding_utxo),
        IssuanceInput::new_issuance(amount * 2, 0, [1u8; 32]),
        RequiredSignature::NativeEcdsa,
    );
    for _ in 0..2 {
        voucher.attach_voucher_creation(&mut ft, amount, issuance.asset_id);
    }

    wait_for_confirmation(&signer.broadcast(&ft)?)?;

    Ok(issuance.asset_id)
}

fn permissionless_fixture(amount: u64) -> (SimplicityNetwork, Voucher, UTXO) {
    let network = SimplicityNetwork::default_regtest();
    let params = VoucherParameters {
        storm_eye_asset_id: AssetId::from_byte_array([1; 32]),
        auth_method: VoucherAuthMethod::Asset {
            auth_asset_id: AssetId::from_byte_array([2; 32]),
        },
        network,
    };
    let voucher = if amount == 1 {
        let keypair = Keypair::from_secret_key(
            &Secp256k1::new(),
            &SecretKey::from_slice(&[42; 32]).unwrap(),
        );
        Voucher::new_with_taproot_pubkey(params, keypair.x_only_public_key().0)
    } else {
        Voucher::new(params)
    };
    let utxo = UTXO {
        outpoint: OutPoint::new(Txid::from_byte_array([3; 32]), 0),
        txout: TxOut {
            asset: confidential::Asset::Explicit(AssetId::from_byte_array([4; 32])),
            value: confidential::Value::Explicit(amount),
            script_pubkey: voucher.get_script_pubkey(),
            ..Default::default()
        },
        secrets: None,
    };
    (network, voucher, utxo)
}

fn permissionless_transaction(voucher: &Voucher, utxo: &UTXO) -> FinalTransaction {
    let mut ft = FinalTransaction::new();
    voucher.attach_spend(
        &mut ft,
        utxo,
        VoucherSpendPath::PermissionlessBurn {
            voucher_output_index: 0,
        },
    );
    voucher.attach_voucher_output(&mut ft, utxo, 0);
    ft
}

fn execute_voucher(
    ft: &FinalTransaction,
    network: &SimplicityNetwork,
    input_index: usize,
    version: u32,
) -> Result<(), simplex::program::ProgramError> {
    let (mut pset, _) = ft.extract_pst();
    pset.global.tx_data.version = version;
    let input = ft.inputs()[input_index].program_input.as_ref().unwrap();
    input
        .program
        .execute(&pset, &input.witness, input_index, network)
        .map(|_| ())
}

#[test]
fn permissionless_burn_checks_this_inputs_bip68_delay() {
    assert_eq!(u32::from(PERMISSIONLESS_BURN_DELAY_INTERVALS) * 512, 4_608);
    for amount in [VOUCHER_TIMESTAMP, 1] {
        let (network, voucher, utxo) = permissionless_fixture(amount);
        let ft = permissionless_transaction(&voucher, &utxo);
        let (pset, _) = ft.extract_pst();
        assert_eq!(pset.global.tx_data.version, 2);
        assert_eq!(
            pset.inputs()[0].sequence,
            Some(Sequence::from_512_second_intervals(9))
        );
        for version in [2, 3, 0x7fff_ffff] {
            execute_voucher(&ft, &network, 0, version).unwrap();
        }
        for version in [0, 1, 0x8000_0002, u32::MAX] {
            assert!(execute_voucher(&ft, &network, 0, version).is_err());
        }

        for sequence in [0x0040_0009, 0x0040_000a, 0x0040_ffff, 0x4040_0009] {
            let mut tx = ft.clone();
            tx.inputs_mut()[0].partial_input = tx.inputs()[0]
                .partial_input
                .clone()
                .with_sequence(Sequence(sequence));
            execute_voucher(&tx, &network, 0, 2).unwrap();
        }
        for sequence in [0, 8, 9, 0x0040_0000, 0x0040_0008, 0x8040_0009, u32::MAX] {
            let mut tx = ft.clone();
            tx.inputs_mut()[0].partial_input = tx.inputs()[0]
                .partial_input
                .clone()
                .with_sequence(Sequence(sequence));
            let mut other = utxo.clone();
            other.outpoint.vout = 1;
            tx.add_input(
                PartialInput::new(other).with_sequence(Sequence::from_512_second_intervals(9)),
                RequiredSignature::None,
            );
            assert!(
                execute_voucher(&tx, &network, 0, 2).is_err(),
                "voucher sequence {sequence:#x} was accepted using another input's delay"
            );
        }
    }
}

#[test]
fn permissionless_burn_requires_the_full_same_asset_in_a_tagged_unspendable_output() {
    for amount in [VOUCHER_TIMESTAMP, 1] {
        let (network, voucher, utxo) = permissionless_fixture(amount);
        let ft = permissionless_transaction(&voucher, &utxo);
        execute_voucher(&ft, &network, 0, 2).unwrap();
        for output in [
            PartialOutput::new(Script::from(vec![0x51]), amount, utxo.asset()),
            op_return_output(amount, utxo.asset()),
            burn_output(1, amount, utxo.asset()),
            burn_output(0, amount - 1, utxo.asset()),
            burn_output(0, amount + 1, utxo.asset()),
            burn_output(0, amount, AssetId::from_byte_array([5; 32])),
        ] {
            let mut tx = ft.clone();
            tx.outputs_mut()[0] = output;
            assert!(execute_voucher(&tx, &network, 0, 2).is_err());
        }
        let mut missing = ft.clone();
        missing.remove_output(0);
        assert!(execute_voucher(&missing, &network, 0, 2).is_err());
        let mut out_of_range = ft.clone();
        out_of_range.inputs_mut()[0]
            .program_input
            .as_mut()
            .unwrap()
            .witness = VoucherSpendPath::PermissionlessBurn {
            voucher_output_index: 1,
        }
        .build_witness()
        .into();
        assert!(execute_voucher(&out_of_range, &network, 0, 2).is_err());
    }
}

#[test]
fn permissionless_burns_cannot_share_one_burn_output() {
    for amount in [VOUCHER_TIMESTAMP, 1] {
        let (network, voucher, utxo) = permissionless_fixture(amount);
        let mut ft = permissionless_transaction(&voucher, &utxo);
        let mut second = utxo.clone();
        second.outpoint.vout = 1;
        voucher.attach_spend(
            &mut ft,
            &second,
            VoucherSpendPath::PermissionlessBurn {
                voucher_output_index: 0,
            },
        );
        ft.add_output(PartialOutput::new(
            Script::from(vec![0x51]),
            amount,
            utxo.asset(),
        ));
        execute_voucher(&ft, &network, 0, 2).unwrap();
        assert!(execute_voucher(&ft, &network, 1, 2).is_err());

        ft.inputs_mut()[1].program_input.as_mut().unwrap().witness =
            VoucherSpendPath::PermissionlessBurn {
                voucher_output_index: 1,
            }
            .build_witness()
            .into();
        ft.outputs_mut()[1] = burn_output(1, amount, utxo.asset());
        execute_voucher(&ft, &network, 0, 2).unwrap();
        execute_voucher(&ft, &network, 1, 2).unwrap();
    }
}

#[test]
fn permissionless_burn_matures_at_exactly_nine_time_intervals() -> anyhow::Result<()> {
    use bitcoincore_rpc::{Auth, RpcApi};
    use simplex::provider::ProviderError;

    #[derive(simplex::serde::Deserialize)]
    #[serde(crate = "simplex::serde")]
    struct Header {
        mediantime: u64,
    }

    // Own the node so mock time can never affect a configured external network.
    let (client, _) = smplx_regtest::Regtest::from_config(&Default::default())?;
    let mut config = simplex::TestConfig::default();
    config.esplora.get_or_insert_default().url = client.esplora_url();
    let rpc_config = config.rpc.get_or_insert_default();
    rpc_config.url = client.rpc_url();
    let Auth::UserPass(username, password) = client.auth() else {
        anyhow::bail!("dedicated regtest did not provide username/password authentication");
    };
    rpc_config.username = username;
    rpc_config.password = password;
    let context = simplex::TestContext::from_config(config)?.regular()?;
    let signer = context.get_default_signer();
    let rpc = &client.elements.client;
    let median_time = |height| -> anyhow::Result<u64> {
        Ok(rpc
            .call::<Header>(
                "getblockheader",
                &[rpc.get_block_hash(height)?.to_string().into()],
            )?
            .mediantime)
    };
    let assert_immature = |tx: &simplex::simplicityhl::elements::Transaction| match context
        .get_default_provider()
        .broadcast_transaction(tx)
    {
        Err(ProviderError::BroadcastRejected { message, .. })
            if message.contains("non-BIP68-final") => {}
        other => panic!("expected consensus relative-time rejection, got {other:?}"),
    };
    let is_unspent = |outpoint: OutPoint| -> anyhow::Result<bool> {
        Ok(rpc
            .call::<Option<simplex::serde::de::IgnoredAny>>(
                "gettxout",
                &[outpoint.txid.to_string().into(), outpoint.vout.into()],
            )?
            .is_some())
    };
    let assert_burned =
        |tx: &simplex::simplicityhl::elements::Transaction, utxo: &UTXO| -> anyhow::Result<()> {
            assert_eq!(tx.output[0].asset.explicit(), Some(utxo.explicit_asset()));
            assert_eq!(tx.output[0].value.explicit(), Some(utxo.explicit_amount()));
            assert!(
                !is_unspent(utxo.outpoint)?,
                "voucher input is still unspent"
            );
            assert!(
                !is_unspent(OutPoint::new(tx.txid(), 0))?,
                "burn output remains in the spendable UTXO set"
            );
            Ok(())
        };
    let storm_eye_asset = issue_asset(&context, STORM_EYE_SUPPLY)?;

    for amount in [VOUCHER_TIMESTAMP, 1] {
        let params = VoucherParameters {
            storm_eye_asset_id: storm_eye_asset,
            auth_method: VoucherAuthMethod::Asset {
                auth_asset_id: AssetId::from_byte_array([2; 32]),
            },
            network: *context.get_network(),
        };
        let voucher = if amount == 1 {
            Voucher::new_with_taproot_pubkey(params, signer.get_schnorr_public_key())
        } else {
            Voucher::new(params)
        };
        let asset = issue_voucher(&context, &voucher, amount)?;
        let origin = median_time(rpc.get_block_count()? - 1)?;
        let utxos = context
            .get_default_provider()
            .fetch_scripthash_utxos(&voucher.get_script_pubkey())?;
        assert_eq!(utxos.len(), 2);
        for utxo in &utxos {
            assert!(is_unspent(utxo.outpoint)?);
        }

        let network_utxo = &utxos[1];
        let storm_eye_utxo = signer.get_utxos_asset(storm_eye_asset)?[0].clone();
        let mut network_ft = FinalTransaction::new();
        voucher.attach_spend(
            &mut network_ft,
            network_utxo,
            VoucherSpendPath::NetworkAuth {
                storm_eye_input_index: 1,
            },
        );
        network_ft.add_input(
            PartialInput::new(storm_eye_utxo.clone()),
            RequiredSignature::NativeEcdsa,
        );
        network_ft.add_output(op_return_output(amount, asset));
        network_ft.add_output(PartialOutput::new(
            signer.get_address().script_pubkey(),
            storm_eye_utxo.explicit_amount(),
            storm_eye_asset,
        ));
        let (network_tx, _) = signer.finalize(&network_ft)?;
        assert!(network_tx.input[0].sequence.is_final());
        assert!(median_time(rpc.get_block_count()?)? < origin + 4_608);
        wait_for_confirmation(
            &context
                .get_default_provider()
                .broadcast_transaction(&network_tx)?,
        )?;
        assert_eq!(
            network_tx.output[0].script_pubkey,
            Script::new_op_return(&[])
        );
        assert_burned(&network_tx, network_utxo)?;

        let utxo = &utxos[0];
        let ft = permissionless_transaction(&voucher, utxo);
        let (tx, _) = signer.finalize(&ft)?;
        assert_immature(&tx);

        for (elapsed, mature) in [(4_607_u64, false), (4_608, true)] {
            let target = origin + elapsed;
            rpc.call::<()>("setmocktime", &[target.into()])?;
            rpc.call::<Vec<String>>(
                "generatetoaddress",
                &[6.into(), signer.get_address().to_string().into()],
            )?;
            assert_eq!(median_time(rpc.get_block_count()?)?, target);
            if mature {
                let mut non_burn = ft.clone();
                non_burn.outputs_mut()[0] =
                    PartialOutput::new(signer.get_address().script_pubkey(), amount, asset);
                assert_covenant_rejects(&context, &non_burn);
                wait_for_confirmation(&context.get_default_provider().broadcast_transaction(&tx)?)?;
            } else {
                assert_immature(&tx);
            }
        }
        assert_burned(&tx, utxo)?;
        assert_eq!(tx.output[0].script_pubkey, Voucher::get_burn_script(0));
        assert_eq!(
            context
                .get_default_provider()
                .fetch_scripthash_utxos(&voucher.get_script_pubkey())?
                .len(),
            0
        );
        let kind = if amount == 1 { "Verifier" } else { "Tick" };
        println!(
            "{kind}: network burn confirmed before expiry; permissionless burn rejected at \
             4607s and confirmed at 4608s; both inputs spent and burn outputs unspendable"
        );
    }
    Ok(())
}

#[simplex::test]
fn rejects_network_burn_without_storm_eye(context: simplex::TestContext) -> anyhow::Result<()> {
    let fixture = VoucherFixture::new(&context, AuthMethodKind::Asset)?;

    let decoy_asset = issue_asset(&context, STORM_EYE_SUPPLY)?;
    assert_ne!(decoy_asset, fixture.storm_eye_asset);
    let decoy_utxo = context.get_default_signer().get_utxos_asset(decoy_asset)?[0].clone();

    let ft = fixture.burn_transaction(
        &context,
        &fixture.voucher_utxos(&context)?[0],
        &decoy_utxo,
        VoucherSpendPath::NetworkAuth {
            storm_eye_input_index: 1,
        },
        op_return_output(VOUCHER_TIMESTAMP, fixture.voucher_asset),
    )?;

    assert_covenant_rejects(&context, &ft);

    Ok(())
}

#[simplex::test]
fn rejects_burn_to_a_spendable_output(context: simplex::TestContext) -> anyhow::Result<()> {
    let fixture = VoucherFixture::new(&context, AuthMethodKind::Asset)?;
    let auth_utxo = fixture.auth_utxo(&context)?;

    let ft = fixture.burn_transaction(
        &context,
        &fixture.voucher_utxos(&context)?[0],
        &auth_utxo,
        VoucherSpendPath::AssetAuth {
            auth_input_index: 1,
            voucher_output_index: 0,
        },
        PartialOutput::new(
            context.get_default_signer().get_address().script_pubkey(),
            VOUCHER_TIMESTAMP,
            fixture.voucher_asset,
        ),
    )?;

    assert_covenant_rejects(&context, &ft);

    Ok(())
}

#[simplex::test]
fn rejects_burn_that_does_not_preserve_the_amount(
    context: simplex::TestContext,
) -> anyhow::Result<()> {
    let fixture = VoucherFixture::new(&context, AuthMethodKind::Asset)?;
    let auth_utxo = fixture.auth_utxo(&context)?;

    let ft = fixture.burn_transaction(
        &context,
        &fixture.voucher_utxos(&context)?[0],
        &auth_utxo,
        VoucherSpendPath::AssetAuth {
            auth_input_index: 1,
            voucher_output_index: 0,
        },
        burn_output(0, VOUCHER_TIMESTAMP - 1, fixture.voucher_asset),
    )?;

    assert_covenant_rejects(&context, &ft);

    Ok(())
}

/// A plain OP_RETURN no longer counts: the burn must be tagged with the voucher's input.
#[simplex::test]
fn rejects_an_untagged_burn(context: simplex::TestContext) -> anyhow::Result<()> {
    let fixture = VoucherFixture::new(&context, AuthMethodKind::Asset)?;
    let auth_utxo = fixture.auth_utxo(&context)?;

    let ft = fixture.burn_transaction(
        &context,
        &fixture.voucher_utxos(&context)?[0],
        &auth_utxo,
        VoucherSpendPath::AssetAuth {
            auth_input_index: 1,
            voucher_output_index: 0,
        },
        op_return_output(VOUCHER_TIMESTAMP, fixture.voucher_asset),
    )?;

    assert_covenant_rejects(&context, &ft);

    Ok(())
}

#[simplex::test]
fn rejects_a_burn_tagged_for_another_input(context: simplex::TestContext) -> anyhow::Result<()> {
    let fixture = VoucherFixture::new(&context, AuthMethodKind::Asset)?;
    let auth_utxo = fixture.auth_utxo(&context)?;

    let ft = fixture.burn_transaction(
        &context,
        &fixture.voucher_utxos(&context)?[0],
        &auth_utxo,
        VoucherSpendPath::AssetAuth {
            auth_input_index: 1,
            voucher_output_index: 0,
        },
        burn_output(1, VOUCHER_TIMESTAMP, fixture.voucher_asset),
    )?;

    assert_covenant_rejects(&context, &ft);

    Ok(())
}

/// The tag, not the position, links a voucher to its burn: each voucher may name any output.
#[simplex::test]
fn burns_two_vouchers_to_their_own_tagged_outputs(
    context: simplex::TestContext,
) -> anyhow::Result<()> {
    let fixture = VoucherFixture::new(&context, AuthMethodKind::Asset)?;
    let auth_utxo = fixture.auth_utxo(&context)?;
    let voucher_utxos = fixture.voucher_utxos(&context)?;
    assert_eq!(voucher_utxos.len(), 2);

    // Input 0 names output 2; output 0 is input 2's burn, tagged 2.
    let mut ft = fixture.burn_transaction(
        &context,
        &voucher_utxos[0],
        &auth_utxo,
        VoucherSpendPath::AssetAuth {
            auth_input_index: 1,
            voucher_output_index: 2,
        },
        burn_output(2, VOUCHER_TIMESTAMP, fixture.voucher_asset),
    )?;
    // Input 2 names output 0; output 2 is input 0's burn, tagged 0.
    fixture.voucher.attach_spend(
        &mut ft,
        &voucher_utxos[1],
        VoucherSpendPath::AssetAuth {
            auth_input_index: 1,
            voucher_output_index: 0,
        },
    );
    fixture
        .voucher
        .attach_voucher_output(&mut ft, &voucher_utxos[1], 0);

    context.get_default_signer().broadcast(&ft)?.wait()?;

    Ok(())
}

/// Each voucher checks the output its own witness names. Before burns were tagged, two
/// equal-amount vouchers could both name one OP_RETURN and let the second amount escape to a
/// spendable output.
#[simplex::test]
fn rejects_two_vouchers_sharing_one_burn_output(
    context: simplex::TestContext,
) -> anyhow::Result<()> {
    let fixture = VoucherFixture::new(&context, AuthMethodKind::Asset)?;
    let auth_utxo = fixture.auth_utxo(&context)?;
    let voucher_utxos = fixture.voucher_utxos(&context)?;
    assert_eq!(voucher_utxos.len(), 2);

    let shared_burn = VoucherSpendPath::AssetAuth {
        auth_input_index: 1,
        voucher_output_index: 0,
    };

    // Normal burn
    let mut ft = fixture.burn_transaction(
        &context,
        &voucher_utxos[0],
        &auth_utxo,
        shared_burn,
        burn_output(0, VOUCHER_TIMESTAMP, fixture.voucher_asset),
    )?;

    // The second voucher names the same output 0 ...
    fixture
        .voucher
        .attach_spend(&mut ft, &voucher_utxos[1], shared_burn);

    // ... so its amount can leave through a spendable output.
    ft.add_output(PartialOutput::new(
        context.get_default_signer().get_address().script_pubkey(),
        VOUCHER_TIMESTAMP,
        fixture.voucher_asset,
    ));

    assert_covenant_rejects(&context, &ft);

    Ok(())
}

#[simplex::test]
fn network_authorization_does_not_constrain_voucher_outputs(
    context: simplex::TestContext,
) -> anyhow::Result<()> {
    let fixture = VoucherFixture::new(&context, AuthMethodKind::Asset)?;
    let storm_eye_utxo = fixture.storm_eye_utxo(&context)?;

    let ft = fixture.burn_transaction(
        &context,
        &fixture.voucher_utxos(&context)?[0],
        &storm_eye_utxo,
        VoucherSpendPath::NetworkAuth {
            storm_eye_input_index: 1,
        },
        PartialOutput::new(
            context.get_default_signer().get_address().script_pubkey(),
            VOUCHER_TIMESTAMP,
            fixture.voucher_asset,
        ),
    )?;

    wait_for_confirmation(&context.get_default_signer().broadcast(&ft)?)?;

    Ok(())
}

#[simplex::test]
fn rejects_spending_through_another_auth_method(
    context: simplex::TestContext,
) -> anyhow::Result<()> {
    let fixture = VoucherFixture::new(&context, AuthMethodKind::Asset)?;
    let storm_eye_utxo = fixture.storm_eye_utxo(&context)?;

    let ft = fixture.burn_transaction(
        &context,
        &fixture.voucher_utxos(&context)?[0],
        &storm_eye_utxo,
        VoucherSpendPath::ScriptAuth {
            auth_input_index: 1,
            voucher_output_index: 0,
        },
        burn_output(0, VOUCHER_TIMESTAMP, fixture.voucher_asset),
    )?;

    assert_covenant_rejects(&context, &ft);

    Ok(())
}

/// 1. happy path.
#[simplex::test]
fn burns_voucher_utxo_via_asset_auth(context: simplex::TestContext) -> anyhow::Result<()> {
    let fixture = VoucherFixture::new(&context, AuthMethodKind::Asset)?;
    let auth_utxo = fixture.auth_utxo(&context)?;

    let ft = fixture.burn_transaction(
        &context,
        &fixture.voucher_utxos(&context)?[0],
        &auth_utxo,
        VoucherSpendPath::AssetAuth {
            auth_input_index: 1,
            voucher_output_index: 0,
        },
        burn_output(0, VOUCHER_TIMESTAMP, fixture.voucher_asset),
    )?;

    wait_for_confirmation(&context.get_default_signer().broadcast(&ft)?)?;

    Ok(())
}

/// 2 happy path.
#[simplex::test]
fn burns_voucher_utxo_via_script_auth(context: simplex::TestContext) -> anyhow::Result<()> {
    let fixture = VoucherFixture::new(&context, AuthMethodKind::Script)?;
    let auth_utxo = fixture.auth_utxo(&context)?;

    let ft = fixture.burn_transaction(
        &context,
        &fixture.voucher_utxos(&context)?[0],
        &auth_utxo,
        VoucherSpendPath::ScriptAuth {
            auth_input_index: 1,
            voucher_output_index: 0,
        },
        burn_output(0, VOUCHER_TIMESTAMP, fixture.voucher_asset),
    )?;

    wait_for_confirmation(&context.get_default_signer().broadcast(&ft)?)?;

    Ok(())
}

/// 3 happy path.
#[simplex::test]
fn burns_voucher_utxo_via_signature_auth(context: simplex::TestContext) -> anyhow::Result<()> {
    let fixture = VoucherFixture::new(&context, AuthMethodKind::Signature)?;
    let auth_utxo = fixture.auth_utxo(&context)?;

    let ft = fixture.burn_transaction(
        &context,
        &fixture.voucher_utxos(&context)?[0],
        &auth_utxo,
        VoucherSpendPath::SignatureAuth {
            voucher_output_index: 0,
        },
        burn_output(0, VOUCHER_TIMESTAMP, fixture.voucher_asset),
    )?;

    wait_for_confirmation(&context.get_default_signer().broadcast(&ft)?)?;

    Ok(())
}

/// 4 happy path.
#[simplex::test]
fn burns_voucher_utxo_when_storm_eye_is_present(
    context: simplex::TestContext,
) -> anyhow::Result<()> {
    let fixture = VoucherFixture::new(&context, AuthMethodKind::Asset)?;
    let storm_eye_utxo = fixture.storm_eye_utxo(&context)?;

    let ft = fixture.burn_transaction(
        &context,
        &fixture.voucher_utxos(&context)?[0],
        &storm_eye_utxo,
        VoucherSpendPath::NetworkAuth {
            storm_eye_input_index: 1,
        },
        op_return_output(VOUCHER_TIMESTAMP, fixture.voucher_asset),
    )?;

    wait_for_confirmation(&context.get_default_signer().broadcast(&ft)?)?;

    Ok(())
}

#[simplex::test]
fn burns_multiple_voucher_utxos_to_one_empty_op_return(
    context: simplex::TestContext,
) -> anyhow::Result<()> {
    let fixture = VoucherFixture::new(&context, AuthMethodKind::Asset)?;
    let voucher_utxos = fixture.voucher_utxos(&context)?;
    let storm_eye_utxo = fixture.storm_eye_utxo(&context)?;
    assert_eq!(voucher_utxos.len(), 2);

    let mut transaction = FinalTransaction::new();
    for voucher_utxo in voucher_utxos {
        fixture.voucher.attach_spend(
            &mut transaction,
            &voucher_utxo,
            VoucherSpendPath::NetworkAuth {
                storm_eye_input_index: 2,
            },
        );
    }
    transaction.add_input(
        PartialInput::new(storm_eye_utxo.clone()),
        RequiredSignature::NativeEcdsa,
    );
    transaction.add_output(op_return_output(
        VOUCHER_TIMESTAMP * 2,
        fixture.voucher_asset,
    ));
    transaction.add_output(PartialOutput::new(
        context.get_default_signer().get_address().script_pubkey(),
        storm_eye_utxo.explicit_amount(),
        storm_eye_utxo.explicit_asset(),
    ));

    wait_for_confirmation(&context.get_default_signer().broadcast(&transaction)?)?;

    Ok(())
}
