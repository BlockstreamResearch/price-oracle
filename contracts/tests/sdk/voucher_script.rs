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
        "78f352902bd0a539848dad38389f9d5ead152d49bb494b220765bb0ff7ad8c35"
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
            "ex1pnewh9rcdzyqx65srv3cp4pxahxh6yjvvwtaw85fckdekqdm3uttscflvq5",
        ),
        (
            SimplicityNetwork::LiquidTestnet,
            "tex1pnewh9rcdzyqx65srv3cp4pxahxh6yjvvwtaw85fckdekqdm3uttsesdt3m",
        ),
        (
            SimplicityNetwork::default_regtest(),
            "ert1pnewh9rcdzyqx65srv3cp4pxahxh6yjvvwtaw85fckdekqdm3utts0yqwxr",
        ),
    ] {
        assert_eq!(
            account.as_ref().get_tr_address(&network).to_string(),
            expected_address
        );
        assert_eq!(
            format!("{:x}", account.get_script_pubkey(&network)),
            "51209e5d728f0d11006d520364701a84ddb9afa2498c72fae3d138b373603771e2d7"
        );
        let mut actual = Vec::new();
        let mut expected = Vec::new();
        for (method, expected_leaf, expected_script) in [
            (
                VoucherAuthMethod::Signature {
                    auth_pubkey: x_only([0x1f; 32]).serialize(),
                },
                "d4d648685d1728e5e73b8e6dda55d5d25251e7750e09644f7adb5027dab5b3ba",
                "5120e41c2cceff59748998f4c6d0540b870ba2c726e9e350b7f7d95b88ed3408a3c8",
            ),
            (
                VoucherAuthMethod::Script { auth_script_hash },
                "b65e44c00e48ca8956a138a4553f3ed376ea253e5b3881e7db3d42157dd8a462",
                "5120a8e28c5f060c0d9d45d50cf7e4bc79077cb17abede7438af92791a2eb10632f3",
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
fn legacy_voucher_keeps_its_pre_upgrade_script() {
    use contracts::artifacts::voucher_legacy::VoucherLegacyProgram;
    use contracts::voucher::{VoucherAuthMethod, VoucherParameters};
    use simplex::provider::SimplicityNetwork;
    use simplex::simplicityhl::elements::AssetId;

    let params = VoucherParameters {
        storm_eye_asset_id: AssetId::from_byte_array([1; 32]),
        auth_method: VoucherAuthMethod::Signature {
            auth_pubkey: x_only([0x1f; 32]).serialize(),
        },
        network: SimplicityNetwork::default_regtest(),
    };
    let legacy = VoucherLegacyProgram::new(params.build_arguments());
    assert_eq!(
        TapNodeHash::from_byte_array(legacy.get_tapleaf_hash()).to_string(),
        "cb926f0b19654c6513e4bd89f8a354a8ab313c6b190c5541ae3da22e14edd8a8"
    );
    assert_eq!(
        format!("{:x}", legacy.get_script_pubkey(&params.network)),
        "5120265faf88d7ee1325f627a1720ecb0d939e135ceab9b928c235cc6f911229e563"
    );
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
