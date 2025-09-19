//! Reshareable Threshold Scheme

use alloc::collections::BTreeMap;

use crate::keys::KeyPackage;
use crate::keys::{
    dkg::round1, 
    generate_secret_polynomial, PublicKeyPackage,};
use crate::{
    Ciphersuite, CryptoRng, Error, Field, Group, Header, Identifier, RngCore, SigningKey
};

use super::{SecretShare, SigningShare};

/// compute signing share for a new participant from an existing key package and old signing key
pub fn computing_new_participant_subshare<C: Ciphersuite, R: RngCore + CryptoRng>(
    old_signing_key: &SigningKey<C>, 
    key_package: round1::SecretPackage<C>,
    new_identifier: Identifier<C>,
) -> Result<SecretShare<C>, Error<C>> {

    // using the same polynomial generation as in refresh
    let (coefficients, commitment) =
        generate_secret_polynomial(&old_signing_key, *key_package.max_signers(), *key_package.min_signers(), key_package.coefficients())?;

    let signing_share = SigningShare::from_coefficients(&coefficients, new_identifier);
    let sec_share = SecretShare::new(new_identifier, signing_share, commitment);
    Ok(sec_share)
}

/// aggregate the recovered shares into a new key package and public key package for a new participant
pub fn aggregate_shares<C: Ciphersuite>(recovered_shares: BTreeMap<Identifier<C>, SecretShare<C>>) -> Result<(KeyPackage<C>, PublicKeyPackage<C>), Error<C>>{

    let mut recovered_signing_share = <<C::Group as Group>::Field>::zero();
    for (sender, share) in &recovered_shares {
        let _ = share.verify().map_err(|_| Error::InvalidSecretShare { culprit: Some(*sender) })?;
        recovered_signing_share = recovered_signing_share + share.signing_share.to_scalar();
    }

    let signing_share = SigningShare::new(recovered_signing_share);
    let verifying_share = signing_share.into();

    let commitments = recovered_shares.iter().map(|(id, share)| (*id, &share.commitment)).collect::<BTreeMap<_, _>>();
    let pubkey = PublicKeyPackage::from_dkg_commitments(&commitments)?;

    let key_package = KeyPackage {
        header: Header::default(),
        identifier: *recovered_shares.keys().next().ok_or(Error::IncorrectNumberOfPackages)?,
        signing_share: signing_share.clone(),
        verifying_share,
        verifying_key: pubkey.verifying_key,
        min_signers: commitments.len() as u16,
    };

    Ok((key_package, pubkey))
}
