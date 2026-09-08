//! 3. Voucher contract (spec §3.4).

#[path = "common/mod.rs"]
mod common;

use common::{assert_covenant_rejects, issue_asset};

use simplex::either::Either;
use simplex::simplicityhl::elements::{AssetId, Script};
use simplex::transaction::partial_input::IssuanceInput;
use simplex::transaction::utxo::UTXO;
use simplex::transaction::{
    FinalTransaction, PartialInput, PartialOutput, ProgramInput, RequiredSignature,
};
use simplex::utils::hash_script;

use contracts::artifacts::voucher::VoucherProgram;
use contracts::artifacts::voucher::derived_voucher::{VoucherArguments, VoucherWitness};

const STORM_EYE_SUPPLY: u64 = 10_000;
const AUTH_ASSET_SUPPLY: u64 = 10_000;

/// Timestamp encoded in amount.
const VOUCHER_TIMESTAMP: u64 = 1_700_000_000;

const AUTH_METHOD_ASSET: u32 = 0;
const AUTH_METHOD_SCRIPT: u32 = 1;
const AUTH_METHOD_SIGNATURE: u32 = 2;

type VoucherPath = Either<Either<(u32, u32), (u32, u32)>, Either<([u8; 64], u32), u32>>;

/// One constructor per spending path, in the order `voucher.simf` declares them.
mod path {
    use super::{Either, VoucherPath};

    pub fn asset_auth(input_index: u32, output_index: u32) -> VoucherPath {
        Either::Left(Either::Left((input_index, output_index)))
    }

    pub fn script_auth(input_index: u32, output_index: u32) -> VoucherPath {
        Either::Left(Either::Right((input_index, output_index)))
    }

    pub fn sign_auth(output_index: u32) -> VoucherPath {
        Either::Right(Either::Left(([0u8; 64], output_index)))
    }

    pub fn network_auth(input_index: u32) -> VoucherPath {
        Either::Right(Either::Right(input_index))
    }
}

fn op_return_output(amount: u64, asset: AssetId) -> PartialOutput {
    PartialOutput::new(Script::new_op_return(&[]), amount, asset)
}

struct VoucherFixture {
    program: VoucherProgram,
    storm_eye_asset: AssetId,
    voucher: AssetId,
    /// Carries `AUTH_ASSET_ID`, and sits at the signer's address.
    auth_asset: AssetId,
}

impl VoucherFixture {
    fn new(context: &simplex::TestContext, auth_method: u32) -> anyhow::Result<Self> {
        let signer = context.get_default_signer();

        let storm_eye_asset = issue_asset(context, STORM_EYE_SUPPLY)?;
        let auth_asset = issue_asset(context, AUTH_ASSET_SUPPLY)?;

        let program = VoucherProgram::new(&VoucherArguments {
            storm_eye_asset_id: storm_eye_asset.into_inner().to_byte_array(),
            auth_method,
            auth_asset_id: auth_asset.into_inner().to_byte_array(),
            auth_script_hash: hash_script(&signer.get_address().script_pubkey()),
            auth_pubkey: signer.get_schnorr_public_key().serialize(),
        });

        let voucher = issue_voucher(context, &program)?;

        Ok(Self {
            program,
            storm_eye_asset,
            voucher,
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
        let script_pubkey = self.program.get_script_pubkey(context.get_network());

        Ok(context
            .get_default_provider()
            .fetch_scripthash_utxos(&script_pubkey)?)
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
        path: VoucherPath,
        required_signature: RequiredSignature,
        burn_output: PartialOutput,
    ) -> anyhow::Result<FinalTransaction> {
        let signer = context.get_default_signer();
        let voucher_utxo = self.voucher_utxo(context)?;

        let mut ft = FinalTransaction::new();

        // Input 0: the Voucher UTXO under the covenant.
        ft.add_program_input(
            PartialInput::new(voucher_utxo.clone()),
            ProgramInput::new(
                Box::new(self.program.as_ref().clone()),
                Box::new(VoucherWitness { path }),
            ),
            required_signature,
        );
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
    program: &VoucherProgram,
) -> anyhow::Result<AssetId> {
    let signer = context.get_default_signer();
    let funding_utxo = signer.get_utxos_asset(context.get_network().policy_asset())?[0].clone();

    let mut ft = FinalTransaction::new();

    let issuance = ft.add_issuance_input(
        PartialInput::new(funding_utxo),
        IssuanceInput::new_issuance(VOUCHER_TIMESTAMP * 2, 0, [1u8; 32]),
        RequiredSignature::NativeEcdsa,
    );
    for _ in 0..2 {
        ft.add_output(PartialOutput::new(
            program.get_script_pubkey(context.get_network()),
            VOUCHER_TIMESTAMP,
            issuance.asset_id,
        ));
    }

    signer.broadcast(&ft)?.wait()?;

    Ok(issuance.asset_id)
}

#[simplex::test]
fn rejects_network_burn_without_storm_eye(context: simplex::TestContext) -> anyhow::Result<()> {
    let fixture = VoucherFixture::new(&context, AUTH_METHOD_ASSET)?;

    let decoy_asset = issue_asset(&context, STORM_EYE_SUPPLY)?;
    assert_ne!(decoy_asset, fixture.storm_eye_asset);
    let decoy_utxo = context.get_default_signer().get_utxos_asset(decoy_asset)?[0].clone();

    let ft = fixture.burn_transaction(
        &context,
        &decoy_utxo,
        path::network_auth(1),
        RequiredSignature::None,
        op_return_output(VOUCHER_TIMESTAMP, fixture.voucher),
    )?;

    assert_covenant_rejects(&context, &ft);

    Ok(())
}

#[simplex::test]
fn rejects_burn_to_a_spendable_output(context: simplex::TestContext) -> anyhow::Result<()> {
    let fixture = VoucherFixture::new(&context, AUTH_METHOD_ASSET)?;
    let auth_utxo = fixture.auth_utxo(&context)?;

    let ft = fixture.burn_transaction(
        &context,
        &auth_utxo,
        path::asset_auth(1, 0),
        RequiredSignature::None,
        PartialOutput::new(
            context.get_default_signer().get_address().script_pubkey(),
            VOUCHER_TIMESTAMP,
            fixture.voucher,
        ),
    )?;

    assert_covenant_rejects(&context, &ft);

    Ok(())
}

#[simplex::test]
fn rejects_burn_that_does_not_preserve_the_amount(
    context: simplex::TestContext,
) -> anyhow::Result<()> {
    let fixture = VoucherFixture::new(&context, AUTH_METHOD_ASSET)?;
    let auth_utxo = fixture.auth_utxo(&context)?;

    let ft = fixture.burn_transaction(
        &context,
        &auth_utxo,
        path::asset_auth(1, 0),
        RequiredSignature::None,
        op_return_output(VOUCHER_TIMESTAMP - 1, fixture.voucher),
    )?;

    assert_covenant_rejects(&context, &ft);

    Ok(())
}

#[simplex::test]
fn network_authorization_does_not_constrain_voucher_outputs(
    context: simplex::TestContext,
) -> anyhow::Result<()> {
    let fixture = VoucherFixture::new(&context, AUTH_METHOD_ASSET)?;
    let storm_eye_utxo = fixture.storm_eye_utxo(&context)?;

    let ft = fixture.burn_transaction(
        &context,
        &storm_eye_utxo,
        path::network_auth(1),
        RequiredSignature::None,
        PartialOutput::new(
            context.get_default_signer().get_address().script_pubkey(),
            VOUCHER_TIMESTAMP,
            fixture.voucher,
        ),
    )?;

    context.get_default_signer().broadcast(&ft)?.wait()?;

    Ok(())
}

#[simplex::test]
fn rejects_spending_through_another_auth_method(
    context: simplex::TestContext,
) -> anyhow::Result<()> {
    let fixture = VoucherFixture::new(&context, AUTH_METHOD_ASSET)?;
    let storm_eye_utxo = fixture.storm_eye_utxo(&context)?;

    let ft = fixture.burn_transaction(
        &context,
        &storm_eye_utxo,
        path::script_auth(1, 0),
        RequiredSignature::None,
        op_return_output(VOUCHER_TIMESTAMP, fixture.voucher),
    )?;

    assert_covenant_rejects(&context, &ft);

    Ok(())
}

/// §3.4.1. happy path.
#[simplex::test]
fn burns_voucher_utxo_via_asset_auth(context: simplex::TestContext) -> anyhow::Result<()> {
    let fixture = VoucherFixture::new(&context, AUTH_METHOD_ASSET)?;
    let auth_utxo = fixture.auth_utxo(&context)?;

    let ft = fixture.burn_transaction(
        &context,
        &auth_utxo,
        path::asset_auth(1, 0),
        RequiredSignature::None,
        op_return_output(VOUCHER_TIMESTAMP, fixture.voucher),
    )?;

    context.get_default_signer().broadcast(&ft)?.wait()?;

    Ok(())
}

/// 2 happy path.
#[simplex::test]
fn burns_voucher_utxo_via_script_auth(context: simplex::TestContext) -> anyhow::Result<()> {
    let fixture = VoucherFixture::new(&context, AUTH_METHOD_SCRIPT)?;
    let auth_utxo = fixture.auth_utxo(&context)?;

    let ft = fixture.burn_transaction(
        &context,
        &auth_utxo,
        path::script_auth(1, 0),
        RequiredSignature::None,
        op_return_output(VOUCHER_TIMESTAMP, fixture.voucher),
    )?;

    context.get_default_signer().broadcast(&ft)?.wait()?;

    Ok(())
}

/// 3 happy path.
#[simplex::test]
fn burns_voucher_utxo_via_signature_auth(context: simplex::TestContext) -> anyhow::Result<()> {
    let fixture = VoucherFixture::new(&context, AUTH_METHOD_SIGNATURE)?;
    let auth_utxo = fixture.auth_utxo(&context)?;

    let ft = fixture.burn_transaction(
        &context,
        &auth_utxo,
        path::sign_auth(0),
        RequiredSignature::witness_with_path("PATH", ["Right", "Left", "0"]),
        op_return_output(VOUCHER_TIMESTAMP, fixture.voucher),
    )?;

    context.get_default_signer().broadcast(&ft)?.wait()?;

    Ok(())
}

/// 4 happy path.
#[simplex::test]
fn burns_voucher_utxo_when_storm_eye_is_present(
    context: simplex::TestContext,
) -> anyhow::Result<()> {
    let fixture = VoucherFixture::new(&context, AUTH_METHOD_ASSET)?;
    let storm_eye_utxo = fixture.storm_eye_utxo(&context)?;

    let ft = fixture.burn_transaction(
        &context,
        &storm_eye_utxo,
        path::network_auth(1),
        RequiredSignature::None,
        op_return_output(VOUCHER_TIMESTAMP, fixture.voucher),
    )?;

    context.get_default_signer().broadcast(&ft)?.wait()?;

    Ok(())
}

#[simplex::test]
fn burns_multiple_voucher_utxos_to_one_empty_op_return(
    context: simplex::TestContext,
) -> anyhow::Result<()> {
    let fixture = VoucherFixture::new(&context, AUTH_METHOD_ASSET)?;
    let voucher_utxos = fixture.voucher_utxos(&context)?;
    let storm_eye_utxo = fixture.storm_eye_utxo(&context)?;
    assert_eq!(voucher_utxos.len(), 2);

    let mut transaction = FinalTransaction::new();
    for voucher_utxo in voucher_utxos {
        transaction.add_program_input(
            PartialInput::new(voucher_utxo),
            ProgramInput::new(
                Box::new(fixture.program.as_ref().clone()),
                Box::new(VoucherWitness {
                    path: path::network_auth(2),
                }),
            ),
            RequiredSignature::None,
        );
    }
    transaction.add_input(
        PartialInput::new(storm_eye_utxo.clone()),
        RequiredSignature::NativeEcdsa,
    );
    transaction.add_output(op_return_output(VOUCHER_TIMESTAMP * 2, fixture.voucher));
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
