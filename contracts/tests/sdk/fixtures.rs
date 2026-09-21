use simplex::either::Either;
use simplex::program::{Program, WitnessTrait};
use simplex::provider::SimplicityNetwork;
use simplex::simplicityhl::elements::secp256k1_zkp::{
    Keypair, Message, Secp256k1, SecretKey, XOnlyPublicKey,
};
use simplex::simplicityhl::elements::{AssetId, Script};
use simplex::transaction::partial_input::IssuanceInput;
use simplex::transaction::utxo::UTXO;
use simplex::transaction::{
    FinalTransaction, PartialInput, PartialOutput, ProgramInput, RequiredSignature,
};

use contracts::auth::{StormTreeBloom, WITNESS_DEPTH};
use contracts::sdk::SignedPrice;
use contracts::voucher::{Voucher, VoucherAuthMethod, VoucherParameters, VoucherSpendPath};
use price_feed::PriceFeedData;

pub use super::common::{assert_covenant_rejects, issue_asset};

pub const SUPPLY: u64 = 10_000;

/// Time carried by the Tick, in seconds.
pub const TICK_TIME: u64 = 1_700_000_000;

pub const ORACLE_SECRET: [u8; 32] = [0x11; 32];
pub const OTHER_SECRET: [u8; 32] = [0x22; 32];

pub fn keypair(secret: [u8; 32]) -> Keypair {
    Keypair::from_secret_key(
        &Secp256k1::new(),
        &SecretKey::from_slice(&secret).expect("valid secret"),
    )
}

pub fn x_only(secret: [u8; 32]) -> XOnlyPublicKey {
    keypair(secret).x_only_public_key().0
}

pub fn asset_bytes(asset: AssetId) -> [u8; 32] {
    asset.into_inner().to_byte_array()
}

/// Signs `price` as the network would, and returns it the way a `signed-price-data` response
/// carries it: inside a Bloom, whose proof consumers ignore.
pub fn network_signed_price(
    signer: XOnlyPublicKey,
    signing_secret: [u8; 32],
    price: PriceFeedData,
) -> SignedPrice {
    let signature = Secp256k1::new()
        .sign_schnorr_no_aux_rand(
            &Message::from_digest(SignedPrice::message_for(&price)),
            &keypair(signing_secret),
        )
        .serialize();

    SignedPrice::from_bloom(
        price,
        &StormTreeBloom {
            signature,
            branch: signer.serialize(),
            proof: [Either::Left(()); WITNESS_DEPTH],
        },
    )
}

/// Issues `amount` of a new asset, paid out by `attach_output`.
pub fn issue(
    context: &simplex::TestContext,
    amount: u64,
    attach_output: impl FnOnce(&mut FinalTransaction, u64, AssetId),
) -> anyhow::Result<AssetId> {
    let signer = context.get_default_signer();
    let funding_utxo = signer.get_utxos_asset(context.get_network().policy_asset())?[0].clone();

    let mut ft = FinalTransaction::new();
    let issuance = ft.add_issuance_input(
        PartialInput::new(funding_utxo),
        IssuanceInput::new_issuance(amount, 0, [1u8; 32]),
        RequiredSignature::NativeEcdsa,
    );
    attach_output(&mut ft, amount, issuance.asset_id);

    signer.broadcast(&ft)?.wait()?;

    Ok(issuance.asset_id)
}

/// A test consumer program: the contract that imports `sdk::voucher`.
pub struct Consumer {
    program: Program,
    network: SimplicityNetwork,
}

impl Consumer {
    pub fn new(program: &impl AsRef<Program>, network: SimplicityNetwork) -> Self {
        Self {
            program: program.as_ref().clone(),
            network,
        }
    }

    /// A consumer holding one UTXO of its own, so it can be spent.
    pub fn funded(
        context: &simplex::TestContext,
        program: &impl AsRef<Program>,
    ) -> anyhow::Result<Self> {
        let consumer = Self::new(program, *context.get_network());
        issue(context, SUPPLY, |ft, amount, asset| {
            consumer.attach_output(ft, amount, asset);
        })?;

        Ok(consumer)
    }

    pub fn get_script_pubkey(&self) -> Script {
        self.program.get_script_pubkey(&self.network)
    }

    pub fn get_utxo(&self, context: &simplex::TestContext) -> anyhow::Result<UTXO> {
        Ok(context
            .get_default_provider()
            .fetch_scripthash_utxos(&self.get_script_pubkey())?[0]
            .clone())
    }

    pub fn attach_spend(
        &self,
        ft: &mut FinalTransaction,
        utxo: &UTXO,
        witness: impl WitnessTrait + 'static,
    ) {
        ft.add_program_input(
            PartialInput::new(utxo.clone()),
            ProgramInput::new(Box::new(self.program.clone()), Box::new(witness)),
            RequiredSignature::None,
        );
    }

    pub fn attach_output(&self, ft: &mut FinalTransaction, amount: u64, asset_id: AssetId) {
        ft.add_output(PartialOutput::new(
            self.get_script_pubkey(),
            amount,
            asset_id,
        ));
    }

    /// Spends this consumer alone, returning its UTXO to itself.
    pub fn spend(
        &self,
        context: &simplex::TestContext,
        witness: impl WitnessTrait + 'static,
    ) -> anyhow::Result<FinalTransaction> {
        let mut ft = FinalTransaction::new();

        let utxo = self.get_utxo(context)?;
        self.attach_spend(&mut ft, &utxo, witness);
        self.attach_output(&mut ft, utxo.explicit_amount(), utxo.explicit_asset());

        Ok(ft)
    }

    /// Spends this consumer at input 0, with `vouchers` at inputs 1.. each burned to the
    /// output with its own index, and the UTXO authorising those burns last.
    pub fn spend_with_vouchers(
        &self,
        context: &simplex::TestContext,
        witness: impl WitnessTrait + 'static,
        vouchers: &[&Voucher],
        auth_asset: AssetId,
    ) -> anyhow::Result<FinalTransaction> {
        let signer = context.get_default_signer();
        let provider = context.get_default_provider();
        let auth_input_index = u32::try_from(1 + vouchers.len())?;

        let mut ft = self.spend(context, witness)?;

        for (offset, voucher) in vouchers.iter().enumerate() {
            // The consumer holds input and output 0, so each voucher's slot is `1 + offset`.
            let index = u32::try_from(1 + offset)?;
            let voucher_utxo =
                provider.fetch_scripthash_utxos(&voucher.get_script_pubkey())?[0].clone();
            voucher.attach_spend(
                &mut ft,
                &voucher_utxo,
                VoucherSpendPath::AssetAuth {
                    auth_input_index,
                    voucher_output_index: index,
                },
            );
            voucher.attach_voucher_output(&mut ft, &voucher_utxo, index);
        }

        let auth_utxo = signer.get_utxos_asset(auth_asset)?[0].clone();
        ft.add_input(
            PartialInput::new(auth_utxo.clone()),
            RequiredSignature::NativeEcdsa,
        );
        ft.add_output(PartialOutput::new(
            signer.get_address().script_pubkey(),
            auth_utxo.explicit_amount(),
            auth_utxo.explicit_asset(),
        ));

        Ok(ft)
    }
}

/// Voucher parameters under asset auth, and the asset that authorises burning them.
pub struct VoucherIssuer {
    storm_eye_asset: AssetId,
    auth_asset: AssetId,
    network: SimplicityNetwork,
}

impl VoucherIssuer {
    pub fn new(context: &simplex::TestContext) -> anyhow::Result<Self> {
        Ok(Self {
            storm_eye_asset: issue_asset(context, SUPPLY)?,
            auth_asset: issue_asset(context, SUPPLY)?,
            network: *context.get_network(),
        })
    }

    pub fn get_auth_asset(&self) -> AssetId {
        self.auth_asset
    }

    pub fn get_parameters(&self) -> VoucherParameters {
        VoucherParameters {
            storm_eye_asset_id: self.storm_eye_asset,
            auth_method: VoucherAuthMethod::Asset {
                auth_asset_id: self.auth_asset,
            },
            network: self.network,
        }
    }

    /// Issues `amount` of a new voucher asset to `voucher`.
    pub fn issue(
        &self,
        context: &simplex::TestContext,
        voucher: &Voucher,
        amount: u64,
    ) -> anyhow::Result<AssetId> {
        issue(context, amount, |ft, amount, asset| {
            voucher.attach_voucher_creation(ft, amount, asset);
        })
    }

    /// A Tick carrying [`TICK_TIME`].
    pub fn issue_tick(&self, context: &simplex::TestContext) -> anyhow::Result<(Voucher, AssetId)> {
        let tick = Voucher::new(self.get_parameters());
        let asset = self.issue(context, &tick, TICK_TIME)?;

        Ok((tick, asset))
    }

    /// A Verifier committed to `key`.
    pub fn issue_verifier(
        &self,
        context: &simplex::TestContext,
        key: XOnlyPublicKey,
    ) -> anyhow::Result<(Voucher, AssetId)> {
        let verifier = Voucher::new_with_taproot_pubkey(self.get_parameters(), key);
        let asset = self.issue(context, &verifier, 1)?;

        Ok((verifier, asset))
    }
}
