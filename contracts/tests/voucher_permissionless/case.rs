use simplex::either::Either;
use simplex::fuzz::{Expect, FuzzCase};
use simplex::provider::SimplicityNetwork;
use simplex::simplicityhl::elements::{AssetId, OutPoint, Script, Sequence, Txid};
use simplex::transaction::utxo::UTXO;
use simplex::transaction::{FinalTransaction, PartialInput, PartialOutput};
use simplex::utils::hash_script;

use contracts::artifacts::voucher::VoucherProgram;
use contracts::artifacts::voucher::derived_voucher::{VoucherArguments, VoucherWitness};
use contracts::voucher::{
    PERMISSIONLESS_BURN_DELAY_INTERVALS, Voucher, VoucherAuthMethod, VoucherParameters,
    VoucherSpendPath,
};

use super::common::case::DispatchCase;
use super::common::unit::{self, UnitTx};

/// The witness path of the permissionless burn: `Right(Right(Right(output_index)))`.
pub const PERMISSIONLESS_PATH: [&str; 3] = ["Right", "Right", "Right"];

/// The name the voucher is added to every scenario with.
pub const VOUCHER: &str = "voucher";

const VOUCHER_AMOUNT: u64 = 1_700_000_000;
const VOUCHER_ASSET: [u8; 32] = [4; 32];

pub fn voucher() -> Voucher {
    Voucher::new(VoucherParameters {
        storm_eye_asset_id: AssetId::from_byte_array([1; 32]),
        auth_method: VoucherAuthMethod::Asset {
            auth_asset_id: AssetId::from_byte_array([2; 32]),
        },
        network: SimplicityNetwork::default_regtest(),
    })
}

/// The delay the SDK sets: the shortest one the burn accepts.
pub fn minimum_delay() -> Sequence {
    Sequence::from_512_second_intervals(PERMISSIONLESS_BURN_DELAY_INTERVALS)
}

// The rules, computed independently of the contract.

/// BIP68: a time-based relative lock of at least nine 512-second intervals.
pub fn sequence_allows_burn(sequence: u32) -> bool {
    sequence & 0x8040_0000 == 0x0040_0000 && sequence & 0xffff >= 9
}

/// BIP68 applies to versions 2 and up; the top bit makes a version negative.
pub fn version_allows_burn(version: u32) -> bool {
    (2..=0x7fff_ffff).contains(&version)
}

/// What the contract must decide for a case of the engine, from its transaction.
pub fn expected_permissionless_burn(case: &FuzzCase<'_>) -> Expect {
    // Where the voucher input ended up after the mutations.
    let voucher_input = case.input_index(0);

    // The engine generates the witness too, so read which output it points at.
    let Either::Right(Either::Right(Either::Right(burn_output))) =
        case.program::<VoucherProgram>(VOUCHER).witness().path
    else {
        unreachable!("the scenario fixes the permissionless path")
    };
    let burn_output = burn_output as usize;

    let burn_ok = case.transaction().n_outputs() > burn_output
        && case.output_script_hash(burn_output)
            == hash_script(&Voucher::get_burn_script(voucher_input as u32))
        && case.output_asset(burn_output) == case.input_asset(voucher_input)
        && case.output_amount(burn_output) == case.input_amount(voucher_input);
    let sequence = case.input_sequence(voucher_input).to_consensus_u32();

    if burn_ok && sequence_allows_burn(sequence) {
        Expect::Accept
    } else {
        Expect::Reject
    }
}

// Transactions for the engine.

fn voucher_utxo(voucher: &Voucher) -> UTXO {
    UTXO::explicit(
        OutPoint::new(Txid::from_byte_array([3; 32]), 0),
        voucher.get_script_pubkey(),
        VOUCHER_AMOUNT,
        AssetId::from_byte_array(VOUCHER_ASSET),
    )
}

/// A permissionless burn as the SDK builds it: the voucher at input 0 with the minimum
/// delay, its tagged burn at output 0.
pub fn permissionless_transaction() -> FinalTransaction {
    let voucher = voucher();
    let utxo = voucher_utxo(&voucher);

    let mut ft = FinalTransaction::new();
    voucher.attach_spend(
        &mut ft,
        &utxo,
        VoucherSpendPath::PermissionlessBurn {
            voucher_output_index: 0,
        },
    );
    voucher.attach_voucher_output(&mut ft, &utxo, 0);
    ft
}

// Unit cases.

/// A valid burn to `output_index`: the minimum delay, version 2, and a burn of the whole
/// input at output 0, tagged for input 0.
pub fn permissionless_burn(output_index: u32) -> Case {
    Case {
        output_index,
        burn: Some(Burn {
            tagged_input: 0,
            amount: unit::AMOUNT,
        }),
        sequence: minimum_delay().to_consensus_u32(),
        version: 2,
        neighbour: None,
    }
}

#[derive(Clone, Copy, Debug)]
struct Burn {
    tagged_input: u32,
    amount: u64,
}

#[derive(Clone, Copy, Debug)]
pub struct Case {
    output_index: u32,
    burn: Option<Burn>,
    sequence: u32,
    version: u32,
    neighbour: Option<Sequence>,
}

impl Case {
    pub fn sequence(mut self, sequence: u32) -> Self {
        self.sequence = sequence;
        self
    }

    pub fn version(mut self, version: u32) -> Self {
        self.version = version;
        self
    }

    /// A second input, which is not the voucher, with its own sequence.
    pub fn neighbour(mut self, sequence: Sequence) -> Self {
        self.neighbour = Some(sequence);
        self
    }

    pub fn burn_tagged_for(mut self, tagged_input: u32) -> Self {
        if let Some(burn) = &mut self.burn {
            burn.tagged_input = tagged_input;
        }
        self
    }

    pub fn burn_amount(mut self, amount: u64) -> Self {
        if let Some(burn) = &mut self.burn {
            burn.amount = amount;
        }
        self
    }

    /// No burn output: output 0 is the unit transaction's plain `OP_TRUE` output.
    pub fn without_burn(mut self) -> Self {
        self.burn = None;
        self
    }
}

impl DispatchCase for Case {
    type Program = VoucherProgram;

    const PROGRAM_NAME: &'static str = VOUCHER;

    fn arguments() -> VoucherArguments {
        voucher().get_parameters().build_arguments()
    }

    fn into_witness(self) -> VoucherWitness {
        VoucherSpendPath::PermissionlessBurn {
            voucher_output_index: self.output_index,
        }
        .build_witness()
    }

    fn unit_tx(&self) -> UnitTx {
        let leading_outputs = self
            .burn
            .map(|burn| {
                PartialOutput::new(
                    Voucher::get_burn_script(burn.tagged_input),
                    burn.amount,
                    unit::asset(),
                )
            })
            .into_iter()
            .collect();

        let trailing_inputs = self
            .neighbour
            .map(|sequence| {
                let utxo = UTXO::explicit(
                    OutPoint::new(Txid::from_byte_array([0xf1; 32]), 0),
                    Script::new(),
                    unit::AMOUNT,
                    unit::asset(),
                );
                PartialInput::new(utxo).with_sequence(sequence)
            })
            .into_iter()
            .collect();

        UnitTx {
            leading_outputs,
            trailing_inputs,
            sequence: Some(Sequence(self.sequence)),
            version: Some(self.version),
        }
    }
}
