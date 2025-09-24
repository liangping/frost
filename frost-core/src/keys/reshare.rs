//! Reshareable Threshold Scheme

use alloc::collections::btree_set::BTreeSet;
use alloc::collections::BTreeMap;

use crate::keys::{KeyPackage, VerifyingShare};
use crate::keys::{
    generate_secret_polynomial, PublicKeyPackage,};
use crate::{
    compute_lagrange_coefficient, Ciphersuite, CryptoRng, Error, Field, Group, Header, Identifier, RngCore, Scalar, SigningKey, VerifyingKey
};

use super::{SecretShare, SigningShare};

pub use super::refresh::*;

/// compute signing share for a new participant from an existing key package and old signing key
/// only run on existing participant nodes. 
pub fn compute_new_participant_subshare<C: Ciphersuite, R: RngCore + CryptoRng>(
    old_key_package: &KeyPackage<C>, 
    old_id_set: &BTreeSet<Identifier<C>>,
    min_signers: u16,
    max_signers: u16,
    mut rng: R,
    new_identifier: Identifier<C>,
) -> Result<SecretShare<C>, Error<C>> {

    // compute the lagrange coefficient for the old participant
    // let lamda_i = compute_lagrange_coefficient(&old_id_set, Some(new_identifier), old_key_package.identifier().clone())?;
    let lamda_i = compute_lagrange_coefficient(&old_id_set, None, old_key_package.identifier().clone())?;
    let secret = SigningKey::from_scalar(old_key_package.signing_share().to_scalar() * lamda_i)?;

    // generate a new polynomial with free term = secret
    let coefficients = super::generate_coefficients::<C, R>(min_signers as usize - 1, &mut rng);
    let (coefficients, commitment) = generate_secret_polynomial(&secret, max_signers, min_signers, coefficients)?;

    // evaluate the polynomial at new_identifier to get the new share
    let restore_share = SigningShare::from_coefficients(&coefficients, new_identifier);
    let secret_share = SecretShare::new(new_identifier, restore_share, commitment);

    Ok(secret_share)
}



/// aggregate the recovered shares into a new key package and public key package for a new participant
pub fn reconstruct_key_from_subshares<C: Ciphersuite>(helper_shares: BTreeMap<Identifier<C>, SecretShare<C>>, new_identifier: Identifier<C>) -> Result<(KeyPackage<C>, PublicKeyPackage<C>), Error<C>>{

    let mut recovered_signing_share = <<C::Group as Group>::Field>::zero();
    // let mut recovered_pubkey =  <<C::Group as Group>::Field>::zero();
    let mut recovered_pubkey = <C::Group>::identity(); // zero element
    let mut verifying_shares = BTreeMap::new();

    // let x_set = helper_shares.keys().map(|id| *id ).collect::<BTreeSet<_>>();
    for (sender, share_i) in &helper_shares {
        let _ = share_i.verify().map_err(|_| Error::InvalidSecretShare { culprit: Some(*sender) })?;

        recovered_signing_share = recovered_signing_share + share_i.signing_share().to_scalar();

        let ci0 =  share_i.commitment().0.get(0).ok_or(Error::IncorrectCommitment)?.value();
        recovered_pubkey =  recovered_pubkey + ci0;

    }

    let signing_share = SigningShare::new(recovered_signing_share);
    let verifying_share = VerifyingShare::from(signing_share);

    if verifying_share.to_element() != recovered_pubkey {
        return Err(Error::InvalidSecretShare { culprit: Some(new_identifier.clone()) });
    }

    verifying_shares.insert(new_identifier, verifying_share.clone());

    //let commitments = helper_shares.iter().map(|(id, share)| (*id, &share.commitment)).collect::<BTreeMap<_, _>>();
    let commitments = helper_shares.values().next().ok_or(Error::IncorrectNumberOfCommitments)?.commitment();

    let verifying_key = VerifyingKey::<C>::new(recovered_pubkey);
    
    let pubkey = PublicKeyPackage::new(verifying_shares, verifying_key);

    let key_package = KeyPackage {
        header: Header::default(),
        identifier: new_identifier,
        signing_share: signing_share.clone(),
        verifying_share,
        verifying_key: pubkey.verifying_key,
        min_signers: (commitments.0.len()) as u16,
    };

    Ok((key_package, pubkey))
}
