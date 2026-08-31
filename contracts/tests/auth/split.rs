//! 4. Authorized splitting of a Storm Eye UTXO into multiple UTXOs (spec §1.4.4).

use simplex::either::Either;
use simplex::transaction::{
    FinalTransaction, PartialInput, PartialOutput, ProgramInput, RequiredSignature,
};

use oracle_contracts::artifacts::auth::AuthProgram;
use oracle_contracts::artifacts::auth::derived_auth::AuthWitness;

use storm_tree::smt::MerkleTree;

use super::covenant::{Branch, WITNESS_DEPTH, WitnessStep, witness_proof};
use super::fixtures::{MAX_SPLIT_UTXOS_COUNT, assert_covenant_rejects, setup_storm_eye};

/// Everything a split transaction needs that does not vary between these tests.
struct SplitFixture {
    program: AuthProgram,
    storm_tree: MerkleTree,
    signing_branch: Branch,
    proof: [WitnessStep; WITNESS_DEPTH],
    rescue_number: u32,
}

impl SplitFixture {
    fn new(context: &simplex::TestContext) -> anyhow::Result<Self> {
        let rescue_number = 1234;
        let (program, storm_tree, signing_branch, _) = setup_storm_eye(context, rescue_number)?;
        let proof = witness_proof(&storm_tree, &signing_branch);

        Ok(Self {
            program,
            storm_tree,
            signing_branch,
            proof,
            rescue_number,
        })
    }

    /// One Storm Eye input declaring `declared_count`, and one covenant output per entry
    /// in `amounts`. The two are separate arguments on purpose: the covenant trusts the
    /// witnessed count, so the negative tests need to disagree with the real output list.
    fn split_transaction(
        &self,
        context: &simplex::TestContext,
        declared_count: u8,
        amounts: &[u64],
    ) -> anyhow::Result<FinalTransaction> {
        let provider = context.get_default_provider();

        let script_pubkey = self.program.get_script_pubkey(context.get_network());
        let storm_eye_utxo = provider.fetch_scripthash_utxos(&script_pubkey)?[0].clone();

        let mut tx = FinalTransaction::new();

        tx.add_program_input(
            PartialInput::new(storm_eye_utxo.clone()),
            ProgramInput::new(
                Box::new(self.program.as_ref().clone()),
                Box::new(AuthWitness {
                    path: Either::Left((
                        (self.storm_tree.root(), self.rescue_number),
                        ([0u8; 64], self.signing_branch, self.proof),
                        // split_utxos_count
                        Either::Right(Either::Right(Either::Left(declared_count))),
                    )),
                }),
            ),
            RequiredSignature::witness_tagged(
                "PATH",
                vec!["Left".to_string(), "1".to_string(), "0".to_string()],
                "OracleNetworkV1/StormEye",
            ),
        );

        // Outputs 0..N-1, same script and asset, so the covenant's loop sees them.
        for amount in amounts {
            tx.add_output(PartialOutput::new(
                script_pubkey.clone(),
                *amount,
                storm_eye_utxo.explicit_asset(),
            ));
        }

        Ok(tx)
    }
}

/// The happy path: any distribution, as long as it sums to the input amount.
#[simplex::test]
fn splits_storm_eye_into_multiple_utxos(context: simplex::TestContext) -> anyhow::Result<()> {
    let fixture = SplitFixture::new(&context)?;
    let amounts = [5_000u64, 3_000, 2_000];

    let tx = fixture.split_transaction(&context, amounts.len() as u8, &amounts)?;
    context.get_default_signer().broadcast(&tx)?.wait()?;

    Ok(())
}

/// Spec §1.4.4 check 6 is `split_utxos_count < MAX_SPLIT_UTXOS_COUNT`, so the bound itself
/// is out of range. Guards against the `lt_8`/`le_8` confusion, which the happy path
/// cannot see because it splits strictly below the bound.
#[simplex::test]
fn rejects_split_at_the_maximum_count(context: simplex::TestContext) -> anyhow::Result<()> {
    let fixture = SplitFixture::new(&context)?;

    let amounts = [4_000u64, 3_000, 2_000, 1_000];
    assert_eq!(amounts.len() as u8, MAX_SPLIT_UTXOS_COUNT);

    let tx = fixture.split_transaction(&context, amounts.len() as u8, &amounts)?;
    assert_covenant_rejects(&context, &tx);

    Ok(())
}

/// Spec §1.4.4 check 6 also demands `split_utxos_count > 1`: a "split" into one output is
/// a plain inclusion and must go through §1.4.1 instead.
#[simplex::test]
fn rejects_split_into_a_single_utxo(context: simplex::TestContext) -> anyhow::Result<()> {
    let fixture = SplitFixture::new(&context)?;
    let amounts = [10_000u64];

    let tx = fixture.split_transaction(&context, amounts.len() as u8, &amounts)?;
    assert_covenant_rejects(&context, &tx);

    Ok(())
}

/// Check 8, value conservation: the outputs the covenant counts must add back up to the
/// amount it is spending, or the remainder leaves the covenant.
#[simplex::test]
fn rejects_split_that_does_not_conserve_value(context: simplex::TestContext) -> anyhow::Result<()> {
    let fixture = SplitFixture::new(&context)?;

    // Declares three outputs but only lets the covenant see two of them, so the third
    // 2_000 is unaccounted for and free to leave.
    let amounts = [5_000u64, 3_000, 2_000];
    let tx = fixture.split_transaction(&context, 2, &amounts)?;

    assert_covenant_rejects(&context, &tx);

    Ok(())
}
