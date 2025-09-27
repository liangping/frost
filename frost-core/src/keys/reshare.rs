//! Reshareable Threshold Scheme

use alloc::collections::btree_set::BTreeSet;
use alloc::collections::BTreeMap;
use alloc::vec::Vec;

use crate::keys::{CoefficientCommitment, KeyPackage, VerifiableSecretSharingCommitment, generate_secret_polynomial, PublicKeyPackage};
use crate::{
    compute_lagrange_coefficient, Ciphersuite, CryptoRng, Error, Field, Group, Identifier, RngCore, SigningKey
};

use super::{SecretShare, SigningShare};

/// select t participants from the old group to help compute the new share
/// generate new partial shares for all participants in `new_id_set`
/// the new polynomial g_i(0) = f_i(i), compute g_ij = g_i(j) for all j in new_id_set
/// returns a map from new participant identifier to their new share
pub fn compute_new_participant_subshare<C: Ciphersuite, R: RngCore + CryptoRng>(
    old_key_package: &KeyPackage<C>, 
    new_id_set: &[Identifier<C>],
    new_min_signers: u16,
    mut rng: R,
) -> Result<BTreeMap<Identifier<C>, SecretShare<C>>, Error<C>> {

    let secret = SigningKey::from_scalar(old_key_package.signing_share().to_scalar()) ?;

    // generate a new polynomial with free term = secret
    let coefficients = super::generate_coefficients::<C, R>(new_min_signers as usize - 1, &mut rng);
    let (coefficients, commitment) = generate_secret_polynomial(&secret, new_id_set.len() as u16, new_min_signers, coefficients)?;

    let gij_map: BTreeMap<Identifier<_>, SecretShare<C>> = new_id_set.iter().map(|new_id| {
        // evaluate the polynomial at new_identifier to get the new share
        let restore_share = SigningShare::from_coefficients(&coefficients, *new_id);
        let secret_share = SecretShare::new(*new_id, restore_share, commitment.clone());
        (*new_id, secret_share)
    }).collect();

    Ok(gij_map)
}

/// aggregate the recovered shares into a new key package and public key package for a new participant
/// `helper_shares` is a map from helper identifier to the share they sent, should be at least t shares. t is the threshold of the old group.
/// `my_identifier` is the identifier of the participant reconstructing their share
/// `new_participants` is the set of all identifiers in the new group
/// returns the new participant's KeyPackage and the PublicKeyPackage for the new group
pub fn reconstruct_key_from_subshares<C: Ciphersuite>(helper_shares: BTreeMap<Identifier<C>, SecretShare<C>>, my_identifier: Identifier<C>, new_participants: &BTreeSet<Identifier<C>>) -> Result<(KeyPackage<C>, PublicKeyPackage<C>), Error<C>>{

    let mut recovered_signing_share = <<C::Group as Group>::Field>::zero();
    let mut commitments = vec![];

    let x_set: BTreeSet<Identifier<C>> = helper_shares.keys().cloned().collect();
    for (sender, share_i) in &helper_shares {
        let _ = share_i.verify().map_err(|_| Error::InvalidSecretShare { culprit: Some(*sender) })?;

        let lamda_i = compute_lagrange_coefficient(&x_set, None, *sender)?;
        recovered_signing_share = recovered_signing_share + share_i.signing_share().to_scalar() * lamda_i;

        let vss = VerifiableSecretSharingCommitment::new(share_i.commitment().coefficients().iter().map(|c| CoefficientCommitment::new(c.value() * lamda_i )).collect::<Vec<_>>());
        commitments.push(vss);

    }

    let group_commitments = crate::keys::sum_commitments(&commitments.iter().map(|c| c).collect::<Vec<_>>())?;
    let public_key_package = PublicKeyPackage::from_commitment(&new_participants, &group_commitments)?;

    let signing_share = SigningShare::new(recovered_signing_share);
    let secret_share = SecretShare::new(my_identifier.clone(), signing_share, group_commitments.clone());
    let key_package = KeyPackage::try_from(secret_share)?;

    // Ok((key_package, public_key_package))
    <C>::post_dkg(key_package, public_key_package)
}
