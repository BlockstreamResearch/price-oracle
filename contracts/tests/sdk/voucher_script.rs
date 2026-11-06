use simplex::simplicityhl::elements::{Script, secp256k1_zkp::Secp256k1, taproot::TapNodeHash};
use simplex::transaction::FinalTransaction;
use simplex::utils::{hash_script, tr_unspendable_key};

use contracts::artifacts::tests::sdk::voucher_script_test::VoucherScriptTestProgram;
use contracts::artifacts::tests::sdk::voucher_script_test::derived_voucher_script_test::{
    VoucherScriptTestArguments, VoucherScriptTestWitness,
};
use contracts::voucher::Voucher;

use super::fixtures::{
    Consumer, ORACLE_SECRET, OTHER_SECRET, VoucherIssuer, assert_covenant_rejects, x_only,
};

#[test]
fn matches_browser_account_vectors() {
    use contracts::artifacts::account::{AccountProgram, derived_account::AccountArguments};
    use contracts::voucher::{VoucherAuthMethod, VoucherParameters};
    use simplex::provider::SimplicityNetwork;
    use simplex::simplicityhl::elements::AssetId;

    let account = AccountProgram::new(&AccountArguments {
        storm_eye_asset_id: [1; 32],
        account_owner_pubkey: x_only([0x1f; 32]).serialize(),
    });

    assert_eq!(
        TapNodeHash::from_byte_array(account.get_tapleaf_hash()).to_string(),
        "d1754012c445c3df09b0d1bec1d6fb3addd9678ccc11e3a2833b5bb6b73a7119"
    );
    assert_eq!(
        tr_unspendable_key().to_string(),
        "50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0"
    );

    let mut auth_script = vec![0, 20];
    auth_script.extend([0x55; 20]);
    let auth_script_hash = hash_script(&Script::from(auth_script));
    for (network, expected_address) in [
        (
            SimplicityNetwork::Liquid,
            "ex1pkmmvkxqa77evn3fvqjuat2dqrf6xnwtnfau9yycpwjh6acsd9ezsv9h7d0",
        ),
        (
            SimplicityNetwork::LiquidTestnet,
            "tex1pkmmvkxqa77evn3fvqjuat2dqrf6xnwtnfau9yycpwjh6acsd9ezsdu9euq",
        ),
        (
            SimplicityNetwork::default_regtest(),
            "ert1pkmmvkxqa77evn3fvqjuat2dqrf6xnwtnfau9yycpwjh6acsd9ezsmggutc",
        ),
    ] {
        assert_eq!(
            account.as_ref().get_tr_address(&network).to_string(),
            expected_address
        );
        assert_eq!(
            format!("{:x}", account.get_script_pubkey(&network)),
            "5120b6f6cb181df7b2c9c52c04b9d5a9a01a7469b9734f7852130174afaee20d2e45"
        );
        let mut actual = Vec::new();
        let mut expected = Vec::new();
        for (method, expected_leaf, expected_script) in [
            (
                VoucherAuthMethod::Signature {
                    auth_pubkey: x_only([0x1f; 32]).serialize(),
                },
                "c94377a3c786b6aefba98ca7e7c2e6ca6a9a4d6ddbdbf20a17fbc32f846be9a4",
                "5120c34ad1035500f2c8e74a71f36e22ff83cb0094b6fe950b86a709b534b4b226e5",
            ),
            (
                VoucherAuthMethod::Script { auth_script_hash },
                "88367e67f5f27e1aa2e906627cc1b57777489d93c7f48554065602d275c1391a",
                "5120f84a9ece5e4fab1c3c166a27e6695bd715058afe75074ff6c879de19495a81b7",
            ),
        ] {
            let voucher = Voucher::new(VoucherParameters {
                storm_eye_asset_id: AssetId::from_byte_array([1; 32]),
                auth_method: method,
                network,
            });
            actual.push((
                TapNodeHash::from_byte_array(voucher.get_tapleaf_hash()).to_string(),
                format!("{:x}", voucher.get_script_pubkey()),
            ));
            expected.push((expected_leaf.to_owned(), expected_script.to_owned()));
        }
        assert_eq!(actual, expected);
    }
}

#[test]
fn matches_browser_verifier_vectors() {
    let branch = x_only([0x1f; 32]);
    let root =
        storm_tree::smt::hash_node(&[3; 32], &storm_tree::smt::hash_leaf(&branch.serialize()));
    assert_eq!(
        TapNodeHash::from_byte_array(root).to_string(),
        "18b14ea9ec5e0932131a6d2b421c992b9cdde6a15059e14da69388174a6b2098"
    );

    let script = Script::new_v1_p2tr(
        &Secp256k1::verification_only(),
        branch,
        Some(TapNodeHash::from_byte_array([5; 32])),
    );
    assert_eq!(
        format!("{script:x}"),
        "512048bd0653a96f933e9132843281a8d981037ca8342a6a8941039293c69d0b8e91"
    );
}

/// Spends a consumer that rebuilds a voucher script from `witness` and compares it with
/// `expected`'s script hash.
fn script_check(
    context: &simplex::TestContext,
    expected: &Voucher,
    witness: VoucherScriptTestWitness,
) -> anyhow::Result<FinalTransaction> {
    let consumer = Consumer::funded(
        context,
        &VoucherScriptTestProgram::new(&VoucherScriptTestArguments {
            expected_script_hash: hash_script(&expected.get_script_pubkey()),
        }),
    )?;

    consumer.spend(context, witness)
}

#[simplex::test]
fn rebuilds_the_script_of_a_verifier(context: simplex::TestContext) -> anyhow::Result<()> {
    let oracle = x_only(ORACLE_SECRET);
    let issuer = VoucherIssuer::new(&context)?;
    let verifier = Voucher::new_with_taproot_pubkey(issuer.get_parameters(), oracle);

    let ft = script_check(
        &context,
        &verifier,
        VoucherScriptTestWitness {
            internal_key: oracle.serialize(),
            tapleaf_hash: verifier.get_tapleaf_hash(),
        },
    )?;

    context.get_default_signer().broadcast(&ft)?.wait()?;

    Ok(())
}

/// A Tick has no key of its own: `Voucher::new` commits to the unspendable key.
#[simplex::test]
fn rebuilds_the_script_of_a_tick(context: simplex::TestContext) -> anyhow::Result<()> {
    let issuer = VoucherIssuer::new(&context)?;
    let tick = Voucher::new(issuer.get_parameters());

    let ft = script_check(
        &context,
        &tick,
        VoucherScriptTestWitness {
            internal_key: tr_unspendable_key().serialize(),
            tapleaf_hash: tick.get_tapleaf_hash(),
        },
    )?;

    context.get_default_signer().broadcast(&ft)?.wait()?;

    Ok(())
}

#[simplex::test]
fn rejects_a_script_rebuilt_from_another_key(context: simplex::TestContext) -> anyhow::Result<()> {
    let issuer = VoucherIssuer::new(&context)?;
    let verifier = Voucher::new_with_taproot_pubkey(issuer.get_parameters(), x_only(ORACLE_SECRET));

    let ft = script_check(
        &context,
        &verifier,
        VoucherScriptTestWitness {
            internal_key: x_only(OTHER_SECRET).serialize(),
            tapleaf_hash: verifier.get_tapleaf_hash(),
        },
    )?;

    assert_covenant_rejects(&context, &ft);

    Ok(())
}
