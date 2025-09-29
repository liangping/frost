//! Reshare Threshold Scheme

use alloc::collections::btree_map::BTreeMap;
use alloc::collections::btree_set::BTreeSet;
use crate::keys::{KeyPackage, PublicKeyPackage};
use crate::{frost, Identifier, Secp256K1Sha256, };
use crate::{Error, CryptoRng, RngCore};

type ReshareSecretShare = frost_core::keys::reshare::ReshareSecretShare<Secp256K1Sha256>;

/// 
pub fn compute_new_participant_subshare<R: RngCore + CryptoRng>(
    old_key_package: &KeyPackage,
    new_id_set: &[Identifier], 
    new_min_signers: u16,
    mut rng: R,
) -> Result<BTreeMap<Identifier, ReshareSecretShare>, Error> {
    frost::keys::reshare::compute_new_participant_subshare(old_key_package, new_id_set, new_min_signers, &mut rng )
}

/// 
pub fn reconstruct_key_from_subshares(helper_shares: BTreeMap<Identifier, ReshareSecretShare>, my_identifier: Identifier, new_participants: &BTreeSet<Identifier>) -> Result<(KeyPackage, PublicKeyPackage), Error>{
    frost::keys::reshare::reconstruct_key_from_subshares(helper_shares, my_identifier, new_participants)
}
