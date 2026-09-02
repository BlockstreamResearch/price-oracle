//! 2. Tick and Verifier inflation tokens contract.

#[path = "common/mod.rs"]
mod common;

use common::{assert_covenant_rejects, issue_asset};

use simplex::simplicityhl::elements::AssetId;
use simplex::transaction::partial_input::IssuanceInput;
use simplex::transaction::utxo::UTXO;
use simplex::transaction::{
    FinalTransaction, PartialInput, PartialOutput, ProgramInput, RequiredSignature,
};

use contracts::artifacts::inflation_tokens::InflationTokensProgram;
use contracts::artifacts::inflation_tokens::derived_inflation_tokens::{
    InflationTokensArguments, InflationTokensWitness,
};

const STORM_EYE_SUPPLY: u64 = 10_000;

const INFLATION_TOKEN_AMOUNT: u64 = 1;
const CONTRACT_HASH: [u8; 32] = [1u8; 32];
const GENESIS_ISSUANCE: u64 = 1;

/// A Tick UTXO's amount is the timestamp it encodes.
const REISSUE_AMOUNT: u64 = 1_700_000_000;

struct InflationFixture {
    program: InflationTokensProgram,
    storm_eye_asset: AssetId,
    /// The asset the token mints. Zero of it exists until a test reissues.
    issued_asset: AssetId,
    /// Ties the issued asset to its token; a reissuance has to present the same value.
    asset_entropy: [u8; 32],
}

impl InflationFixture {
    fn new(context: &simplex::TestContext) -> anyhow::Result<Self> {
        let signer = context.get_default_signer();

        let storm_eye_asset = issue_asset(context, STORM_EYE_SUPPLY)?;

        let program = InflationTokensProgram::new(&InflationTokensArguments {
            storm_eye_asset_id: storm_eye_asset.into_inner().to_byte_array(),
        });

        let funding_utxo = signer.get_utxos_asset(context.get_network().policy_asset())?[0].clone();
        let mut ft = FinalTransaction::new();

        let details = ft.add_issuance_input(
            PartialInput::new(funding_utxo),
            IssuanceInput::new_issuance(GENESIS_ISSUANCE, INFLATION_TOKEN_AMOUNT, CONTRACT_HASH),
            RequiredSignature::NativeEcdsa,
        );
        ft.add_output(PartialOutput::new(
            program.get_script_pubkey(context.get_network()),
            INFLATION_TOKEN_AMOUNT,
            details.inflation_asset_id,
        ));
        ft.add_output(PartialOutput::new(
            signer.get_address().script_pubkey(),
            GENESIS_ISSUANCE,
            details.asset_id,
        ));

        signer.broadcast(&ft)?.wait()?;

        Ok(Self {
            program,
            storm_eye_asset,
            issued_asset: details.asset_id,
            asset_entropy: details.asset_entropy.to_byte_array(),
        })
    }

    fn script_pubkey(
        &self,
        context: &simplex::TestContext,
    ) -> simplex::simplicityhl::elements::Script {
        self.program.get_script_pubkey(context.get_network())
    }

    fn inflation_token_utxo(&self, context: &simplex::TestContext) -> anyhow::Result<UTXO> {
        let script_pubkey = self.script_pubkey(context);

        context
            .get_default_provider()
            .fetch_scripthash_utxos(&script_pubkey)?
            .first()
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("the covenant holds no inflation token"))
    }

    fn storm_eye_utxo(&self, context: &simplex::TestContext) -> anyhow::Result<UTXO> {
        Ok(context
            .get_default_signer()
            .get_utxos_asset(self.storm_eye_asset)?[0]
            .clone())
    }

    /// The output the covenant inspects: the inflation token, back where it came from.
    fn token_returned(&self, context: &simplex::TestContext) -> PartialOutput {
        PartialOutput::new(
            self.script_pubkey(context),
            INFLATION_TOKEN_AMOUNT,
            self.inflation_token_utxo(context)
                .map(|utxo| utxo.explicit_asset())
                .expect("the covenant holds an inflation token"),
        )
    }

    /// Reissues `reissue_amount` of the asset.
    fn reissue_transaction(
        &self,
        context: &simplex::TestContext,
        auth_utxo: &UTXO,
        reissue_amount: u64,
        token_output: PartialOutput,
    ) -> anyhow::Result<FinalTransaction> {
        let signer = context.get_default_signer();
        let token_utxo = self.inflation_token_utxo(context)?;

        let mut ft = FinalTransaction::new();

        // Input 0: the Storm Eye, i.e. the network's authorization.
        ft.add_input(
            PartialInput::new(auth_utxo.clone()),
            RequiredSignature::NativeEcdsa,
        );

        ft.add_program_issuance_input(
            PartialInput::new(token_utxo.clone()),
            ProgramInput::new(
                Box::new(self.program.as_ref().clone()),
                Box::new(InflationTokensWitness {
                    storm_eye_input_index: 0,
                    inflation_token_output_index: 0,
                }),
            ),
            IssuanceInput::new_reissuance(reissue_amount, self.asset_entropy),
            RequiredSignature::None,
        );

        ft.add_output(token_output);

        // Output 1: the newly minted asset.
        if reissue_amount > 0 {
            ft.add_output(PartialOutput::new(
                signer.get_address().script_pubkey(),
                reissue_amount,
                self.issued_asset,
            ));
        }

        // The Storm Eye, handed back untouched.
        ft.add_output(PartialOutput::new(
            signer.get_address().script_pubkey(),
            auth_utxo.explicit_amount(),
            auth_utxo.explicit_asset(),
        ));

        Ok(ft)
    }
}

/// The first happy path.
#[simplex::test]
fn reissues_asset_when_storm_eye_is_present(context: simplex::TestContext) -> anyhow::Result<()> {
    let fixture: InflationFixture = InflationFixture::new(&context)?;
    let storm_eye_utxo = fixture.storm_eye_utxo(&context)?;

    let ft = fixture.reissue_transaction(
        &context,
        &storm_eye_utxo,
        REISSUE_AMOUNT,
        fixture.token_returned(&context),
    )?;

    context.get_default_signer().broadcast(&ft)?.wait()?;

    Ok(())
}

/// The second happy path.
#[simplex::test]
fn reissues_twice_reusing_the_inflation_token(context: simplex::TestContext) -> anyhow::Result<()> {
    let fixture = InflationFixture::new(&context)?;
    let signer = context.get_default_signer();

    for round in 0..2 {
        let storm_eye_utxo = fixture.storm_eye_utxo(&context)?;

        let ft = fixture.reissue_transaction(
            &context,
            &storm_eye_utxo,
            REISSUE_AMOUNT + round,
            fixture.token_returned(&context),
        )?;

        signer.broadcast(&ft)?.wait()?;
    }

    Ok(())
}

#[simplex::test]
fn rejects_reissuance_without_storm_eye(context: simplex::TestContext) -> anyhow::Result<()> {
    let fixture = InflationFixture::new(&context)?;

    let decoy_asset = issue_asset(&context, STORM_EYE_SUPPLY)?;
    assert_ne!(decoy_asset, fixture.storm_eye_asset);
    let decoy_utxo = context.get_default_signer().get_utxos_asset(decoy_asset)?[0].clone();

    let ft = fixture.reissue_transaction(
        &context,
        &decoy_utxo,
        REISSUE_AMOUNT,
        fixture.token_returned(&context),
    )?;

    assert_covenant_rejects(&context, &ft);

    Ok(())
}

#[simplex::test]
fn rejects_reissuance_that_moves_the_inflation_token(
    context: simplex::TestContext,
) -> anyhow::Result<()> {
    let fixture = InflationFixture::new(&context)?;
    let storm_eye_utxo = fixture.storm_eye_utxo(&context)?;
    let token_utxo = fixture.inflation_token_utxo(&context)?;

    // Everything is a valid reissuance except that the token lands elsewhere.
    let ft = fixture.reissue_transaction(
        &context,
        &storm_eye_utxo,
        REISSUE_AMOUNT,
        PartialOutput::new(
            context.get_default_signer().get_address().script_pubkey(),
            INFLATION_TOKEN_AMOUNT,
            token_utxo.explicit_asset(),
        ),
    )?;

    assert_covenant_rejects(&context, &ft);

    Ok(())
}

#[simplex::test]
fn rejects_reissuance_of_zero(context: simplex::TestContext) -> anyhow::Result<()> {
    let fixture = InflationFixture::new(&context)?;
    let storm_eye_utxo = fixture.storm_eye_utxo(&context)?;

    let ft = fixture.reissue_transaction(
        &context,
        &storm_eye_utxo,
        0,
        fixture.token_returned(&context),
    )?;

    assert_covenant_rejects(&context, &ft);

    Ok(())
}
