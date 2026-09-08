//! 3. Voucher contract (spec §3.4).

#[path = "common/mod.rs"]
mod common;

use common::{assert_covenant_rejects, issue_asset};

use simplex::simplicityhl::elements::{AssetId, Script};
use simplex::transaction::partial_input::IssuanceInput;
use simplex::transaction::utxo::UTXO;
use simplex::transaction::{FinalTransaction, PartialInput, PartialOutput, RequiredSignature};
use simplex::utils::hash_script;

use contracts::voucher::{Voucher, VoucherAuthMethod, VoucherParameters, VoucherSpendPath};

const STORM_EYE_SUPPLY: u64 = 10_000;
const AUTH_ASSET_SUPPLY: u64 = 10_000;

/// Timestamp encoded in amount.
const VOUCHER_TIMESTAMP: u64 = 1_700_000_000;

fn op_return_output(amount: u64, asset: AssetId) -> PartialOutput {
    PartialOutput::new(Script::new_op_return(&[]), amount, asset)
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

        let voucher_asset = issue_voucher(context, &voucher)?;

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

    fn voucher_utxo(&self, context: &simplex::TestContext) -> anyhow::Result<UTXO> {
        self.voucher_utxos(context)?
            .into_iter()
            .next()
            .ok_or_else(|| anyhow::anyhow!("the covenant holds no Voucher UTXO"))
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

    /// Spends the Voucher UTXO with `auth_utxo` at input 1 and `burn_output` at output 0.
    fn burn_transaction(
        &self,
        context: &simplex::TestContext,
        auth_utxo: &UTXO,
        path: VoucherSpendPath,
        burn_output: PartialOutput,
    ) -> anyhow::Result<FinalTransaction> {
        let signer = context.get_default_signer();
        let voucher_utxo = self.voucher_utxo(context)?;

        let mut ft = FinalTransaction::new();

        // Input 0: the Voucher UTXO under the covenant.
        self.voucher.attach_spend(&mut ft, &voucher_utxo, path);
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
fn issue_voucher(context: &simplex::TestContext, voucher: &Voucher) -> anyhow::Result<AssetId> {
    let signer = context.get_default_signer();
    let funding_utxo = signer.get_utxos_asset(context.get_network().policy_asset())?[0].clone();

    let mut ft = FinalTransaction::new();

    let issuance = ft.add_issuance_input(
        PartialInput::new(funding_utxo),
        IssuanceInput::new_issuance(VOUCHER_TIMESTAMP * 2, 0, [1u8; 32]),
        RequiredSignature::NativeEcdsa,
    );
    for _ in 0..2 {
        voucher.attach_voucher_output(&mut ft, VOUCHER_TIMESTAMP, issuance.asset_id);
    }

    signer.broadcast(&ft)?.wait()?;

    Ok(issuance.asset_id)
}

#[simplex::test]
fn rejects_network_burn_without_storm_eye(context: simplex::TestContext) -> anyhow::Result<()> {
    let fixture = VoucherFixture::new(&context, AuthMethodKind::Asset)?;

    let decoy_asset = issue_asset(&context, STORM_EYE_SUPPLY)?;
    assert_ne!(decoy_asset, fixture.storm_eye_asset);
    let decoy_utxo = context.get_default_signer().get_utxos_asset(decoy_asset)?[0].clone();

    let ft = fixture.burn_transaction(
        &context,
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
        &auth_utxo,
        VoucherSpendPath::AssetAuth {
            auth_input_index: 1,
            voucher_output_index: 0,
        },
        op_return_output(VOUCHER_TIMESTAMP - 1, fixture.voucher_asset),
    )?;

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

    context.get_default_signer().broadcast(&ft)?.wait()?;

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
        &storm_eye_utxo,
        VoucherSpendPath::ScriptAuth {
            auth_input_index: 1,
            voucher_output_index: 0,
        },
        op_return_output(VOUCHER_TIMESTAMP, fixture.voucher_asset),
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
        &auth_utxo,
        VoucherSpendPath::AssetAuth {
            auth_input_index: 1,
            voucher_output_index: 0,
        },
        op_return_output(VOUCHER_TIMESTAMP, fixture.voucher_asset),
    )?;

    context.get_default_signer().broadcast(&ft)?.wait()?;

    Ok(())
}

/// 2 happy path.
#[simplex::test]
fn burns_voucher_utxo_via_script_auth(context: simplex::TestContext) -> anyhow::Result<()> {
    let fixture = VoucherFixture::new(&context, AuthMethodKind::Script)?;
    let auth_utxo = fixture.auth_utxo(&context)?;

    let ft = fixture.burn_transaction(
        &context,
        &auth_utxo,
        VoucherSpendPath::ScriptAuth {
            auth_input_index: 1,
            voucher_output_index: 0,
        },
        op_return_output(VOUCHER_TIMESTAMP, fixture.voucher_asset),
    )?;

    context.get_default_signer().broadcast(&ft)?.wait()?;

    Ok(())
}

/// 3 happy path.
#[simplex::test]
fn burns_voucher_utxo_via_signature_auth(context: simplex::TestContext) -> anyhow::Result<()> {
    let fixture = VoucherFixture::new(&context, AuthMethodKind::Signature)?;
    let auth_utxo = fixture.auth_utxo(&context)?;

    let ft = fixture.burn_transaction(
        &context,
        &auth_utxo,
        VoucherSpendPath::SignatureAuth {
            voucher_output_index: 0,
        },
        op_return_output(VOUCHER_TIMESTAMP, fixture.voucher_asset),
    )?;

    context.get_default_signer().broadcast(&ft)?.wait()?;

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
        &storm_eye_utxo,
        VoucherSpendPath::NetworkAuth {
            storm_eye_input_index: 1,
        },
        op_return_output(VOUCHER_TIMESTAMP, fixture.voucher_asset),
    )?;

    context.get_default_signer().broadcast(&ft)?.wait()?;

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

    context
        .get_default_signer()
        .broadcast(&transaction)?
        .wait()?;

    Ok(())
}
