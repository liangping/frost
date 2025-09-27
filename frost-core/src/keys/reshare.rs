//! Reshareable Threshold Scheme

use alloc::collections::btree_set::BTreeSet;
use alloc::collections::BTreeMap;
use alloc::vec::Vec;

use crate::keys::{CoefficientCommitment, KeyPackage, VerifiableSecretSharingCommitment, generate_secret_polynomial, PublicKeyPackage};
use crate::{
    compute_lagrange_coefficient, Ciphersuite, CryptoRng, Error, Field, Group, Identifier, RngCore, SigningKey
};

use super::{SecretShare, SigningShare};

/// compute signing share for a new participant from an existing key package and old signing key
/// only run on existing participant nodes. 
pub fn compute_new_participant_subshare<C: Ciphersuite, R: RngCore + CryptoRng>(
    old_key_package: &KeyPackage<C>, 
    new_id_set: &[Identifier<C>],
    new_min_signers: u16,
    mut rng: R,
) -> Result<BTreeMap<Identifier<C>, SecretShare<C>>, Error<C>> {

    // compute the lagrange coefficient for the old secret share
    // let lamda_i = compute_lagrange_coefficient(&old_id_set, None, old_key_package.identifier().clone())?;
    let secret = SigningKey::from_scalar(old_key_package.signing_share().to_scalar()) ?;

    // generate a new polynomial with free term = secret
    let coefficients = super::generate_coefficients::<C, R>(new_min_signers as usize - 1, &mut rng);
    let (coefficients, commitment) = generate_secret_polynomial(&secret, new_id_set.len() as u16, new_min_signers, coefficients)?;

    let gij: BTreeMap<Identifier<_>, SecretShare<C>> = new_id_set.iter().map(|new_id| {
        // evaluate the polynomial at new_identifier to get the new share
        let restore_share = SigningShare::from_coefficients(&coefficients, *new_id);
        let secret_share = SecretShare::new(*new_id, restore_share, commitment.clone());
        (*new_id, secret_share)
    }).collect();

    Ok(gij)
}

/// aggregate the recovered shares into a new key package and public key package for a new participant
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
