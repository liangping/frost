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
    old_signing_key: &SigningKey<C>, 
    min_signers: u16,
    max_signers: u16,
    mut rng: R,
    new_identifier: Identifier<C>,
) -> Result<SecretShare<C>, Error<C>> {

    let coefficients = super::generate_coefficients::<C, R>(min_signers as usize - 1, &mut rng);
    // using the same polynomial generation as in refresh
    let (coefficients, commitment) =
        generate_secret_polynomial(&old_signing_key, max_signers, min_signers, coefficients)?;

    let signing_share = SigningShare::from_coefficients(&coefficients, new_identifier);
    let sec_share = SecretShare::new(new_identifier, signing_share, commitment);

    Ok(sec_share)
}

/// aggregate the recovered shares into a new key package and public key package for a new participant
pub fn reconstruct_key_from_subshares<C: Ciphersuite>(helper_shares: BTreeMap<Identifier<C>, SecretShare<C>>, new_identifier: Identifier<C>) -> Result<(KeyPackage<C>, PublicKeyPackage<C>), Error<C>>{

    let mut recovered_signing_share = <<C::Group as Group>::Field>::zero();
    // let mut recovered_pubkey =  <<C::Group as Group>::Field>::zero();
    let mut recovered_pubkey = <C::Group>::generator() - <C::Group>::generator(); // zero element
    let mut verifying_shares = BTreeMap::new();

    let x_set = helper_shares.keys().map(|id| *id ).collect::<BTreeSet<_>>();
    for (sender, share_i) in &helper_shares {
        let _ = share_i.verify().map_err(|_| Error::InvalidSecretShare { culprit: Some(*sender) })?;
        let lamda_ij = compute_lagrange_coefficient(&x_set, Some(new_identifier), sender.clone())?;

        recovered_signing_share = recovered_signing_share + (share_i.signing_share().to_scalar() * lamda_ij);

        let lamda_i0 = compute_lagrange_coefficient(&x_set, None, sender.clone())?;

        let ci0 =  share_i.commitment().0.get(0).ok_or(Error::IncorrectCommitment)?.value();
        recovered_pubkey =  recovered_pubkey + ci0 * lamda_i0;

        let verifying_share_i = VerifyingShare::new(ci0);
        verifying_shares.insert(*sender, verifying_share_i);

    }

    let signing_share = SigningShare::new(recovered_signing_share);
    let verifying_share = VerifyingShare::from(signing_share);
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
