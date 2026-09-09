use crate::artifacts::auth::AuthProgram;

/// The Storm Eye covenant's two Taproot storage slots.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuthStorage {
    pub merkle_root: [u8; 32],
    pub rescue_block_number: u32,
}

impl AuthStorage {
    /// Slot 1's on-chain encoding: the height widened to 32 bytes, big-endian, matching
    /// `storage.simf`'s `get_rescue_block_slot_leaf`.
    fn rescue_block_slot_value(&self) -> [u8; 32] {
        let mut slot = [0u8; 32];
        slot[28..32].copy_from_slice(&self.rescue_block_number.to_be_bytes());

        slot
    }

    #[allow(unused_must_use)]
    pub(crate) fn apply(&self, program: &mut AuthProgram) {
        program.set_storage_at(0, self.merkle_root);
        program.set_storage_at(1, self.rescue_block_slot_value());
    }
}
